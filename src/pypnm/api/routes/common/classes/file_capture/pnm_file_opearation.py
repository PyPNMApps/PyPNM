# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
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

        return [TransactionId(str(tid)) for tid in txns]

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
