# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging

from pypnm.api.routes.common.classes.file_capture.pnm_file_transaction import (
    PnmFileTransaction,
)
from pypnm.api.routes.common.classes.file_capture.types import TransactionRecordModel
from pypnm.lib.db.capture_group_repository import CaptureGroupRepository
from pypnm.lib.db.operation_capture_repository import OperationCaptureRepository
from pypnm.lib.types import GroupId, OperationId, TransactionId


class OperationCaptureGroupResolver:
    """
    Resolve Operation IDs Into Capture Groups And Transaction Records.

    This helper class ties together DB-backed datasets for operation resolution:

    1) Operation Database
       - DB: operation_captures table (operation_id -> capture_group_id)

    2) Capture Group Database
       - DB: capture_groups/capture_group_transactions tables

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
        self.logger.info("No operation record found for operation_id=%s", operation_id)
        return None

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
        self.logger.info(
            "No capture group record found for capture_group_id=%s",
            capture_group_id,
        )
        return []

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
