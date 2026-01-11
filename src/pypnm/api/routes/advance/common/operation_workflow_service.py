# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.lib.operations.operation_models import OperationStatusModel

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId


class OperationWorkflowService:
    """
    Shared workflow helpers for status, cancel, and result endpoints.
    """

    @staticmethod
    def get_status(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        return status

    @staticmethod
    def cancel(
        operation_id: OperationId, service: AbstractCaptureService | None = None
    ) -> OperationStatusModel:
        store = OperationStore()
        status = store.mark_canceled(operation_id, "Operation canceled")
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        if service is not None:
            service.stop(operation_id)
        return status

    @staticmethod
    def get_result(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        if status.state != OperationExecutionState.COMPLETED:
            raise ValueError("Operation not completed")
        return status


__all__ = ["OperationWorkflowService"]
