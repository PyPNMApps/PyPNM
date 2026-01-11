# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from pypnm.api.routes.advance.common.abstract.service import AbstractService
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.schemas import (
    MultiRxMerResultRequest,
    MultiRxMerResultResponse,
    MultiRxMerStartRequest,
    MultiRxMerStartResponse,
)
from pypnm.api.routes.advance.ds.ofdm.rxmer.multi.service import (
    MultiRxMerWorkflowService,
)
from pypnm.lib.fastapi_constants import FAST_API_RESPONSE


class MultiRxMerWorkflowRouter(AbstractService):
    """
    Router for multi-RxMER workflow start/result endpoints.
    """

    def __init__(self) -> None:
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.router = APIRouter(
            prefix="/advance/ds/ofdm/rxmer/multi",
            tags=["PNM Operations - Multi-RxMER"],
        )
        self._service = MultiRxMerWorkflowService()
        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            "/start",
            response_model=MultiRxMerStartResponse,
            summary="Start a Multi-RxMER capture workflow",
            responses=FAST_API_RESPONSE,
        )
        async def start_capture(
            request: MultiRxMerStartRequest,
        ) -> MultiRxMerStartResponse:
            return await self._service.start(request)

        @self.router.post(
            "/result",
            response_model=MultiRxMerResultResponse,
            summary="Get Multi-RxMER capture results by operation ID",
            responses=FAST_API_RESPONSE,
        )
        def get_result(
            request: MultiRxMerResultRequest,
        ) -> MultiRxMerResultResponse:
            try:
                return self._service.result(request)
            except KeyError as err:
                detail = err.args[0] if err.args else "Operation not found"
                raise HTTPException(status_code=404, detail=detail) from err
            except ValueError as err:
                raise HTTPException(status_code=400, detail=str(err)) from err


router = MultiRxMerWorkflowRouter().router


__all__ = ["MultiRxMerWorkflowRouter", "router"]
