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
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.db.transaction_repository import TransactionRepository
from pypnm.lib.types import GroupId, OperationId, TimestampSec, TransactionId

_DEFAULT_CREATED_EPOCH: int = 0


class OperationCaptureGroupResolver:
    """
    Resolve Operation IDs Into Capture Groups And Transaction Records.

    This helper class ties together DB-backed datasets with legacy JSON fallback:

    1) Operation Database
       - DB: operation_captures table (fallback to SystemConfigSettings.operation_db)
       - Shape:
         {
           "<operation_id>": {
             "capture_group_id": "<capture_group_id>",
             "created": <epoch>
           },
           ...
         }

    2) Capture Group Database
       - DB: capture_groups/capture_group_transactions tables
       - Path: SystemConfigSettings.capture_group_db (fallback)
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

    3) Transaction Database (transaction_records)
       - Already managed by PnmFileTransaction.

    Public APIs:
      - get_capture_group_id(operation_id)
      - get_transaction_ids_for_operation(operation_id)
      - get_transaction_models_for_operation(operation_id)
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()
        self._transaction_repo = TransactionRepository.from_system_config()
        self.operation_db_path = Path(SystemConfigSettings.operation_db())
        self.capture_group_db_path = Path(SystemConfigSettings.capture_group_db())

        self.operation_db_path.parent.mkdir(parents=True, exist_ok=True)
        self.capture_group_db_path.parent.mkdir(parents=True, exist_ok=True)

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
        capture_group_id = self._operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id

        op_db = self._load_json(self.operation_db_path)
        rec = op_db.get(operation_id)
        if not rec:
            self.logger.info(
                "No operation record found for operation_id=%s", operation_id
            )
            return None

        capture_group_id_value = rec.get("capture_group_id")
        if capture_group_id_value:
            capture_group_id = GroupId(str(capture_group_id_value))
        else:
            legacy_capture_group = rec.get("capture_group")
            if legacy_capture_group:
                self.logger.warning(
                    "Operation record for %s uses legacy 'capture_group' field",
                    operation_id,
                )
                capture_group_id = GroupId(str(legacy_capture_group))
            self.logger.warning(
                "Operation record for %s is missing 'capture_group_id' field",
                operation_id,
            )
            if not legacy_capture_group:
                return None

        created_value = rec.get("created")
        created_epoch = int(created_value) if created_value else _DEFAULT_CREATED_EPOCH
        self._capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(created_epoch)
        )
        self._operation_repo.upsert_operation_capture(
            operation_id, capture_group_id, TimestampSec(created_epoch)
        )
        return capture_group_id

    def get_transaction_ids_for_capture_group(
        self, capture_group_id: GroupId
    ) -> list[TransactionId]:
        """
        Resolve All Transaction IDs Belonging To A Capture Group.

        Returns an ordered list of TransactionId values, or an empty list if
        the capture group is unknown or has no associated transactions.
        """
        db_transactions = self._capture_repo.list_transactions(capture_group_id)
        if db_transactions:
            return db_transactions

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

        created_value = rec.get("created")
        created_epoch = int(created_value) if created_value else _DEFAULT_CREATED_EPOCH
        self._capture_repo.get_or_create_capture_group(
            capture_group_id, TimestampSec(created_epoch)
        )

        transaction_ids: list[TransactionId] = []
        for tid in txns:
            tx_id = str(tid)
            if not tx_id.strip():
                self.logger.warning(
                    "Skipping empty transaction_id in capture_group_db for capture_group_id=%s",
                    capture_group_id,
                )
                continue
            transaction_id = TransactionId(tx_id)
            transaction_ids.append(transaction_id)
            if self._transaction_repo.get_transaction_record(transaction_id) is None:
                self.logger.warning(
                    "Skipping capture_group backfill for missing transaction_id=%s",
                    transaction_id,
                )
                continue
            self._capture_repo.add_transaction(
                capture_group_id, transaction_id, TimestampSec(created_epoch)
            )
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
