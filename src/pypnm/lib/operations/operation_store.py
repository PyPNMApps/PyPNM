# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import math
from pathlib import Path

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.types import OperationId, PathLike
from pypnm.lib.utils import Generate


class OperationStore:
    """
    Filesystem-backed operation registry with one JSON file per operation ID.
    """

    _DEFAULT_DIR_NAME: str = "operations"
    _FILE_SUFFIX: str = ".json"
    _MIN_INTERVAL_SECONDS: float = 1.0
    _MIN_PROGRESS_TOTAL: int = 1

    def __init__(self, base_dir: Path | None = None) -> None:
        """
        Initialize the store under the configured .data root.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if base_dir is None:
            pnm_dir = Path(SystemConfigSettings.pnm_dir())
            base_dir = pnm_dir.parent / self._DEFAULT_DIR_NAME
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def estimate_progress_total(duration: float, interval: float) -> int:
        """
        Estimate total work units for a periodic capture workflow.
        """
        effective_interval = (
            interval if interval > 0 else OperationStore._MIN_INTERVAL_SECONDS
        )
        total = int(math.ceil(duration / effective_interval))
        return max(OperationStore._MIN_PROGRESS_TOTAL, total)

    def _operation_path(self, operation_id: OperationId) -> Path:
        filename = f"{operation_id}{self._FILE_SUFFIX}"
        return self.base_dir / filename

    def _atomic_write(self, path: Path, status: OperationStatusModel) -> None:
        temp_path = path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(status.model_dump(), handle, indent=2)
        temp_path.replace(path)

    def create_operation(
        self,
        operation_id: OperationId,
        progress_total: int,
        message: str,
    ) -> OperationStatusModel:
        """
        Create a new operation status record in CREATED state.
        """
        now = Generate.time_stamp()
        status = OperationStatusModel(
            operation_id=operation_id,
            state=OperationExecutionState.CREATED,
            created_ts=now,
            updated_ts=now,
            progress_current=0,
            progress_total=progress_total,
            message=message,
            error=None,
            artifact_paths=None,
        )
        path = self._operation_path(operation_id)
        self._atomic_write(path, status)
        return status

    def update_operation(
        self,
        operation_id: OperationId,
        state: OperationExecutionState,
        progress_current: int,
        progress_total: int,
        message: str,
        error: str | None = None,
        artifact_paths: list[PathLike] | None = None,
    ) -> OperationStatusModel:
        """
        Update and persist operation status.
        """
        now = Generate.time_stamp()
        status = OperationStatusModel(
            operation_id=operation_id,
            state=state,
            created_ts=self._get_created_ts(operation_id, now),
            updated_ts=now,
            progress_current=progress_current,
            progress_total=progress_total,
            message=message,
            error=error,
            artifact_paths=artifact_paths,
        )
        path = self._operation_path(operation_id)
        self._atomic_write(path, status)
        return status

    def _get_created_ts(self, operation_id: OperationId, fallback: int) -> int:
        existing = self.get_operation(operation_id)
        return int(existing.created_ts) if existing else fallback

    def get_operation(self, operation_id: OperationId) -> OperationStatusModel | None:
        """
        Retrieve an operation status record from disk.
        """
        path = self._operation_path(operation_id)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            return OperationStatusModel.model_validate(data)
        except Exception as exc:
            self.logger.error(
                f"Failed to read operation status {operation_id}: {exc}", exc_info=True
            )
            return None

    def mark_canceled(
        self, operation_id: OperationId, message: str
    ) -> OperationStatusModel | None:
        """
        Mark an operation as canceled.
        """
        existing = self.get_operation(operation_id)
        if not existing:
            return None
        return self.update_operation(
            operation_id=operation_id,
            state=OperationExecutionState.CANCELED,
            progress_current=int(existing.progress_current),
            progress_total=int(existing.progress_total),
            message=message,
            error=existing.error,
            artifact_paths=existing.artifact_paths,
        )

    def is_canceled(self, operation_id: OperationId) -> bool:
        """
        Check whether an operation has been canceled.
        """
        status = self.get_operation(operation_id)
        return bool(status and status.state == OperationExecutionState.CANCELED)


__all__ = ["OperationStore"]
