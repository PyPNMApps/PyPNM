# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import cast
from pypnm.lib.db.capture_group_repository import (
    CaptureGroupRepository,
    OperationCaptureRepository,
)
from pypnm.lib.types import GroupId, OperationId, TimestampSec

_DEFAULT_CREATED_EPOCH: int = 0


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
            db_path: Optional path to the operations DB file; if None,
                     retrieves from ConfigManager under
                     [PnmFileRetrieval].operation_db.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capture_group_id: GroupId = capture_group_id
        self.operation_id: OperationId = cast(OperationId, uuid.uuid4().hex[:16])

        self._capture_repo = CaptureGroupRepository.from_system_config()
        self._operation_repo = OperationCaptureRepository.from_system_config()

        # Resolve legacy DB file path (fallback reads only)
        if db_path:
            self.db_path = db_path
        else:
            db_str = SystemConfigSettings.operation_db()
            self.db_path = Path(db_str)

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
            db_path: Optional override for the operations DB file.

        Returns:
            capture_group_id if found, otherwise None.
        """
        logger = logging.getLogger(cls.__name__)
        operation_repo = OperationCaptureRepository.from_system_config()
        capture_repo = CaptureGroupRepository.from_system_config()
        capture_group_id = operation_repo.get_capture_group_id(operation_id)
        if capture_group_id is not None:
            return capture_group_id

        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                db = json.load(f)
            rec = db.get(operation_id)
            if isinstance(rec, dict):
                capture_group_id_value = rec.get("capture_group_id")
                legacy_capture_group = rec.get("capture_group")
                if capture_group_id_value:
                    capture_group_id = GroupId(str(capture_group_id_value))
                elif legacy_capture_group:
                    logger.warning(
                        "Operation record for %s uses legacy 'capture_group' field",
                        operation_id,
                    )
                    capture_group_id = GroupId(str(legacy_capture_group))
                else:
                    return None

                created_value = rec.get("created")
                created_epoch = (
                    int(created_value) if created_value else _DEFAULT_CREATED_EPOCH
                )
                capture_repo.get_or_create_capture_group(
                    capture_group_id, TimestampSec(created_epoch)
                )
                operation_repo.upsert_operation_capture(
                    operation_id, capture_group_id, TimestampSec(created_epoch)
                )
                return capture_group_id
            return None
        except Exception as e:
            logger.error(f"Error retrieving capture group for {operation_id}: {e}")
            return None

    @classmethod
    def list_operations(cls, db_path: Path | None = None) -> list[str]:
        """
        List all registered operation IDs.

        Args:
            db_path: Optional override for the operations DB file.

        Returns:
            List of operation_id strings.
        """
        operation_repo = OperationCaptureRepository.from_system_config()
        operation_ids = operation_repo.list_operation_ids()
        if operation_ids:
            return [str(op_id) for op_id in operation_ids]

        if not db_path:
            db_str = SystemConfigSettings.operation_db()
            db_path = Path(db_str)
        try:
            with db_path.open("r", encoding="utf-8") as f:
                return list(json.load(f).keys())
        except Exception as e:
            logging.getLogger(cls.__name__).error(f"Error listing operations: {e}")
            return []
