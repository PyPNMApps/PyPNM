# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from pypnm.lib.constants import cast
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.types import GroupId, OperationId, TimestampSec


class OperationManager:
    """
    Manager for mapping background capture operations to their capture group IDs.

    Each operation is assigned a unique operation_id and linked to a
    capture_group_id. Mappings are persisted in the DB backend so that
    captures can be looked up later by operation ID.
    """

    def __init__(self, capture_group_id: GroupId, db_path: Path | None = None) -> None:
        """
        Initialize a new operation manager for a given capture group.

        Args:
            capture_group_id: The ID of the capture group to associate.
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_group_id: GroupId = capture_group_id
        self.operation_id: OperationId = cast(OperationId, uuid.uuid4().hex[:16])

        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()

    def register(self) -> OperationId:
        """
        Register this operation with its capture group ID in the DB.

        Verifies that the associated capture group exists before registration.

        Returns:
            The operation_id assigned.

        Raises:
            ValueError: If the capture_group_id is not present in the CaptureGroup database.
        """
        if not self._capture_repo.capture_group_exists(self.capture_group_id):
            raise ValueError(f"CaptureGroup '{self.capture_group_id}' does not exist")

        created_epoch = TimestampSec(int(time.time()))
        self._operation_repo.upsert_operation_capture(
            self.operation_id, self.capture_group_id, created_epoch
        )
        self.logger.info(
            f"Registered operation {self.operation_id} for group {self.capture_group_id}"
        )
        return self.operation_id

    @classmethod
    def get_capture_group(
        cls, operation_id: OperationId, db_path: Path | None = None
    ) -> GroupId | None:
        """
        Retrieve the capture_group_id for a given operation_id.

        Args:
            operation_id: The operation ID to look up.
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.

        Returns:
            capture_group_id if found, otherwise None.
        """
        operation_repo = OperationCaptureRepository.from_system_config()
        capture_group_id = operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id
        return None

    @classmethod
    def list_operations(cls, db_path: Path | None = None) -> list[str]:
        """
        List all registered operation IDs.

        Args:
            db_path: Deprecated legacy JSON path override. Ignored; DB is authoritative.

        Returns:
            List of operation_id strings.
        """
        operation_repo = OperationCaptureRepository.from_system_config()
        operation_ids = operation_repo.list_operation_ids()
        return [str(op_id) for op_id in operation_ids]
