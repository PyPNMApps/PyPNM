# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.common.operation_registry import OperationRegistry
from pypnm.api.routes.advance.common.operation_workflow_schemas import (
    OperationCancelResponse,
    OperationRequest,
    OperationResultResponse,
    OperationStartRequest,
    OperationStartResponse,
    OperationStatusResponse,
)
from pypnm.api.routes.advance.common.operation_workflow_service import (
    OperationWorkflowService,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class OperationWorkflowRouter(AbstractService):
    """
    Generic operation workflow endpoints (start/status/result/cancel).
    """

    _DEFAULT_TIME_REMAINING: int = 0

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/operation",
            tags=["PNM Operations - Workflow"],
        )
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=OperationStartResponse,
            summary="Create a generic operation entry",
            responses=FAST_API_RESPONSE,
        )
        def start_operation(request: OperationStartRequest) -> OperationStartResponse:
            status = OperationWorkflowService.start(
                progress_total=request.progress_total,
                message=request.message,
            )
            return OperationStartResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
                time_remaining=self._DEFAULT_TIME_REMAINING,
            )

        @self.router.post(
            "/status",
            response_model=OperationStatusResponse,
            summary="Get status for an operation ID",
            responses=FAST_API_RESPONSE,
        )
        def get_status(request: OperationRequest) -> OperationStatusResponse:
            try:
                status = OperationWorkflowService.get_status(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            time_remaining = self._DEFAULT_TIME_REMAINING
            service = OperationRegistry.get(request.operation_id)
            if service is not None:
                op_status = service.status(request.operation_id)
                time_remaining = int(op_status.get("time_remaining", time_remaining))
            return OperationStatusResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
                time_remaining=time_remaining,
            )

        @self.router.post(
            "/result",
            response_model=OperationResultResponse,
            summary="Get the final result for an operation ID",
            responses=FAST_API_RESPONSE,
        )
        def get_result(request: OperationRequest) -> OperationResultResponse:
            try:
                status = OperationWorkflowService.get_result(request.operation_id)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err)) from err
            return OperationResultResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
            )

        @self.router.post(
            "/cancel",
            response_model=OperationCancelResponse,
            summary="Cancel an operation by ID",
            responses=FAST_API_RESPONSE,
        )
        def cancel(request: OperationRequest) -> OperationCancelResponse:
            service = OperationRegistry.get(request.operation_id)
            try:
                status = OperationWorkflowService.cancel(request.operation_id, service)
            except KeyError as err:
                raise HTTPException(
                    status_code=404, detail="Operation not found"
                ) from err
            return OperationCancelResponse(
                status="success",
                service_status=ServiceStatusCode.SUCCESS,
                message=None,
                operation=status,
            )


router = OperationWorkflowRouter().router


__all__ = ["OperationWorkflowRouter", "router"]
