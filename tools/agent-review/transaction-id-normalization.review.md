### Summary
Normalized transaction_id linking through a capture-service helper, ensured capture-group persistence strips whitespace, corrected final-invocation timestamps to use Generate.time_stamp(), and added direct tests for whitespace persistence and resolver filtering.

### Modified Files
- src/pypnm/api/routes/advance/common/capture_service.py
- src/pypnm/api/routes/common/classes/file_capture/capture_group.py
- tests/test_capture_group_persistence_normalizes_transaction_id.py

### Commands Executed And Results
- `python3 -m compileall src` → pass
- `ruff check .` → pass
- `ruff format --check .` → pass (356 files already formatted)
- `pytest -q` → pass (550 passed, 4 skipped)

### Tests
- `pytest -q` → pass (550 passed, 4 skipped)
- `ruff check .` → pass
- `ruff format --check .` → pass
- `python3 -m compileall src` → pass

### Notes / Warnings
- pytest emitted expected warning logs from existing tests and transaction-id guards.

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
                iteration_ts = Generate.time_stamp()

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

# FILE: src/pypnm/api/routes/common/classes/file_capture/capture_group.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import time
import uuid
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, TransactionId


class CaptureGroup:
    """
    Manage sessions of capture operations (e.g., multi-RxMER runs) by grouping
    multiple file-transfer transactions under a single UUID-based group ID.

    Features:
      - Persist groups and their transaction lists in a JSON file across runs.
      - Generate or load a 16-character hexadecimal group ID per session.
      - Add, list, delete transactions; prune stale groups.

    JSON schema (DB file):
    {
        "<group_id>": {
            "created": <unix_epoch_seconds>,
            "transactions": ["<txn1>", "<txn2>", ...]
        },
        ...
    }

    Example:
        # New session
        cg = CaptureGroup()
        group_id = cg.create_group()

        # Existing session
        cg2 = CaptureGroup(group_id=group_id)
        txns = cg2.get_transactions()
    """

    def __init__(
        self, group_id: GroupId | None = None, db_path: Path | None = None
    ) -> None:
        """
        Initialize the CaptureGroup manager.

        Args:
            group_id: Optional existing group ID to load; generates a new one if None.
            db_path: Optional Path for the JSON DB file. Defaults to config [PnmFileRetrieval].capture_group_db.

        Raises:
            OSError: If the parent directory cannot be created.
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        # Resolve DB file path
        if db_path:
            self.db_path = Path(db_path)
        else:
            cfg_db_path = SystemConfigSettings.capture_group_db()
            self.db_path = Path(cfg_db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create empty DB if missing
        if not self.db_path.exists():
            self._atomic_write_db({})

        # Load in-memory state
        self._db: dict[str, Any] = {}
        self._grp_id: GroupId = group_id
        self._load_db()
        self._create_group_id()

    def _load_db(self) -> None:
        """
        Load the JSON DB into memory; resets on error.
        """
        try:
            with self.db_path.open("r", encoding="utf-8") as f:
                self._db = json.load(f)
        except (ValueError, JSONDecodeError):
            self.logger.warning("Corrupt DB file; resetting to empty")
            self._db = {}
        except Exception as e:
            self.logger.error(f"Error loading DB: {e}")
            self._db = {}

    def _atomic_write_db(self, data: dict[str, Any]) -> None:
        """
        Atomically write the given data dict to the JSON DB file.
        """
        temp_path = self.db_path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        temp_path.replace(self.db_path)

    def _save_db(self) -> None:
        """
        Persist the in-memory DB to disk using atomic write.
        """
        try:
            self._atomic_write_db(self._db)
        except Exception as e:
            self.logger.error(f"Failed to save DB: {e}")

    def _create_group_id(self) -> str:
        """
        Ensure a group ID is set (use existing or generate new).
        Returns the active group ID.
        """
        if not self._grp_id:
            self._grp_id = uuid.uuid4().hex[:16]
        return self._grp_id

    def get_group_id(self) -> GroupId:
        """
        Get the current active group ID.
        Raises AssertionError if uninitialized.
        """
        assert self._grp_id, "Group ID not initialized"
        return self._grp_id

    def create_group(self) -> GroupId:
        """
        Add the current group to the DB (no-op if exists).
        Returns the group ID.
        """
        gid = self.get_group_id()
        if gid not in self._db:
            self._db[gid] = {"created": int(time.time()), "transactions": []}
            self._save_db()
            self.logger.info(f"Created new group: {gid}")
        else:
            self.logger.debug(f"Group {gid} already exists")
        return gid

    def add_transaction(self, txn_id: str) -> None:
        """
        Append a transaction ID to this group, saving the DB.
        Raises ValueError if group missing.
        """
        tx_id = str(txn_id).strip()
        if not tx_id:
            self.logger.warning("Skipping empty transaction_id persistence")
            return
        gid = self.get_group_id()
        if gid not in self._db:
            raise ValueError("Group not found; create_group() first")
        txns = self._db[gid].setdefault("transactions", [])
        if tx_id not in txns:
            txns.append(tx_id)
            self._save_db()
            self.logger.debug(f"Added txn {tx_id} to group {gid}")

    def getTransactionIds(self) -> list[TransactionId]:
        """
        Return all transaction IDs for this group (empty list if none).
        """
        return list(self._db.get(self.get_group_id(), {}).get("transactions", []))

    def delete_group(self) -> None:
        """
        Remove this group and its transactions from the DB; resets group ID.
        """
        gid = self.get_group_id()
        if gid in self._db:
            del self._db[gid]
            self._save_db()
            self.logger.info(f"Deleted group: {gid}")
        self._grp_id = None

    def list_groups(self) -> list[str]:
        """
        List all group IDs currently in the DB.
        """
        return list(self._db.keys())

    def prune_older_than(self, seconds: int) -> None:
        """
        Remove groups older than the given age (seconds).
        """
        cutoff = int(time.time()) - seconds
        to_delete = [
            gid for gid, info in self._db.items() if info.get("created", 0) < cutoff
        ]
        for gid in to_delete:
            del self._db[gid]
        if to_delete:
            self._save_db()
            self.logger.info(f"Pruned groups: {to_delete}")

# FILE: tests/test_capture_group_persistence_normalizes_transaction_id.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pypnm.api.routes.common.classes.file_capture.capture_group import CaptureGroup
from pypnm.api.routes.common.classes.file_capture.pnm_file_opearation import (
    OperationCaptureGroupResolver,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.types import GroupId, TransactionId


def _configure_capture_group_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    db_path = tmp_path / "capture_group.json"
    monkeypatch.setattr(
        SystemConfigSettings,
        "capture_group_db",
        classmethod(lambda cls: str(db_path)),
    )
    return db_path


def test_capture_group_skips_whitespace_transaction_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    caplog.set_level("WARNING")
    group = CaptureGroup()
    group_id = group.create_group()

    group.add_transaction("   ")

    with db_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert data[str(group_id)]["transactions"] == []
    assert "Skipping empty transaction_id persistence" in caplog.text


def test_resolver_filters_whitespace_transaction_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = _configure_capture_group_db(tmp_path, monkeypatch)
    group_id = GroupId("group-1")
    payload = {
        str(group_id): {
            "created": 1,
            "transactions": ["", "   ", "txn123"],
        }
    }
    db_path.write_text(json.dumps(payload), encoding="utf-8")

    resolver = OperationCaptureGroupResolver()
    txns = resolver.get_transaction_ids_for_capture_group(group_id)

    assert txns == [TransactionId("txn123")]
