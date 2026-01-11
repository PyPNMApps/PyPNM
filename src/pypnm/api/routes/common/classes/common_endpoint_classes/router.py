# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from __future__ import annotations

__skip_autoregister__ = True

import logging
from abc import ABC, abstractmethod
from enum import Enum

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmAnalysisRequest,
    PnmAnalysisResponse,
    PnmMeasurementResponse,
    PnmRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpRequest,
    SnmpResponse,
)


class BaseFastApiRouter:
    def __init__(self, prefix: str, tags: list[str | Enum], base_endpoint: str) -> None:
        self.router = APIRouter(prefix=prefix, tags=tags)
        self.logger = logging.getLogger(f"{self.__class__.__name__}.{base_endpoint}")
        self._base_endpoint = base_endpoint.strip("/")


class PnmFastApiRouter(BaseFastApiRouter, ABC):
    """
    Abstract base router class for defining standardized FastAPI endpoints related to
    Proactive Network Maintenance (PNM).

    Subclasses must implement core logic for:
    - get_measurement_logic
    - get_analysis_logic
    - get_measurement_statistics_logic
    """

    def __init__(
        self,
        prefix: str,
        tags: list[str | Enum],
        base_endpoint: str,
        set_measurement_description: str = None,  # type: ignore
        set_analysis_description: str = None,  # type: ignore
        set_measurement_statistics_description: str = None,
    ) -> None:  # type: ignore
        super().__init__(prefix, tags, base_endpoint)
        self.set_measurement_description = set_measurement_description
        self.set_analysis_description = set_analysis_description
        self.set_measurement_statistics_description = (
            set_measurement_statistics_description
        )

        self._add_routes()

    def _add_routes(self) -> None:
        @self.router.post(
            f"/{self._base_endpoint}/getMeasurement",
            response_model=PnmMeasurementResponse | SnmpResponse,
            description=self.set_measurement_description,
        )
        async def get_measurement(
            request: PnmRequest,
        ) -> PnmMeasurementResponse | SnmpResponse:
            try:
                return await self.get_measurement_logic(request)
            except HTTPException:
                raise
            except Exception as e:
                self.logger.exception(
                    f"[getMeasurement] Error for MAC {request.cable_modem.mac_address}"
                )
                raise HTTPException(
                    status_code=500, detail=f"Measurement retrieval failed: {str(e)}"
                ) from e

        @self.router.post(
            f"/{self._base_endpoint}/getAnalysis",
            response_model=PnmAnalysisResponse | SnmpResponse,
            response_model_exclude_unset=True,
            description=self.set_analysis_description,
        )
        async def get_analysis(
            request: PnmAnalysisRequest,
        ) -> PnmAnalysisResponse | SnmpResponse:
            try:
                return await self.get_analysis_logic(request)
            except HTTPException:
                raise
            except Exception as e:
                self.logger.exception(
                    f"[getAnalysis] Error for MAC {request.cable_modem.mac_address}"
                )
                raise HTTPException(
                    status_code=500, detail=f"Analysis retrieval failed: {str(e)}"
                ) from e

        @self.router.post(
            f"/{self._base_endpoint}/getMeasurementStatistics",
            response_model=SnmpResponse,
            response_model_exclude_unset=True,
            description=self.set_measurement_statistics_description,
        )
        async def get_measurement_statistics(request: SnmpRequest) -> SnmpResponse:
            try:
                return await self.get_measurement_statistics_logic(request)
            except HTTPException:
                raise
            except Exception as e:
                self.logger.exception(
                    f"[getMeasurementStatistics] Error for MAC {request.cable_modem.mac_address}"
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"Measurement Statistics retrieval failed: {str(e)}",
                ) from e

    @abstractmethod
    async def get_measurement_logic(
        self, request: PnmRequest
    ) -> PnmMeasurementResponse | SnmpResponse:
        """Subclasses must implement this to provide measurement data"""
        pass

    @abstractmethod
    async def get_analysis_logic(
        self, request: PnmAnalysisRequest
    ) -> PnmAnalysisResponse | FileResponse | SnmpResponse:
        """Subclasses must implement this to provide analysis data"""
        pass

    @abstractmethod
    async def get_measurement_statistics_logic(
        self, request: SnmpRequest
    ) -> SnmpResponse:
        """Subclasses must implement this to provide measurement statistics data"""
        pass
