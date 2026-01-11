# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.advance.common.operation_registry import OperationServiceProtocol
from pypnm.lib.constants import OperationExecutionState
from pypnm.lib.operations.operation_models import OperationStatusModel
from pypnm.lib.operations.operation_store import OperationStore
from pypnm.lib.types import OperationId
from pypnm.lib.utils import Generate


class OperationWorkflowService:
    """
    Shared workflow helpers for status, cancel, and result endpoints.
    """

    _DEFAULT_PROGRESS_TOTAL: int = 1
    _DEFAULT_START_MESSAGE: str = "Operation created"
    _RUNNING_MESSAGE: str = "Operation running"
    _DEFAULT_OPERATION_ID_LENGTH: int = 16

    @staticmethod
    def start(progress_total: int, message: str | None = None) -> OperationStatusModel:
        store = OperationStore()
        operation_id = OperationId(
            str(
                Generate.operation_id(
                    length=OperationWorkflowService._DEFAULT_OPERATION_ID_LENGTH
                )
            )
        )
        total = max(OperationWorkflowService._DEFAULT_PROGRESS_TOTAL, progress_total)
        created = store.create_operation(
            operation_id=operation_id,
            progress_total=total,
            message=message or OperationWorkflowService._DEFAULT_START_MESSAGE,
        )
        return store.update_operation(
            operation_id=operation_id,
            state=OperationExecutionState.RUNNING,
            progress_current=0,
            progress_total=total,
            message=OperationWorkflowService._RUNNING_MESSAGE,
            error=created.error,
            artifact_paths=created.artifact_paths,
        )

    @staticmethod
    def get_status(operation_id: OperationId) -> OperationStatusModel:
        store = OperationStore()
        status = store.get_operation(operation_id)
        if status is None:
            raise KeyError(f"Operation not found: {operation_id}")
        return status

    @staticmethod
    def cancel(
        operation_id: OperationId, service: OperationServiceProtocol | None = None
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
        if status.state not in {
            OperationExecutionState.COMPLETED,
            OperationExecutionState.CANCELED,
        }:
            raise ValueError("Operation not completed")
        return status


__all__ = ["OperationWorkflowService"]
