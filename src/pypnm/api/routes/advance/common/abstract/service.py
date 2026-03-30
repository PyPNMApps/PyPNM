# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import Any, TypeVar

from pypnm.api.routes.advance.common.capture_service import AbstractCaptureService
from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.lib.types import GroupId, OperationId

T = TypeVar("T", bound=AbstractCaptureService)

class AbstractService:
    """
    Base router class managing the lifecycle of capture service instances.

    Responsibilities:
        - Instantiate and start capture services using load_service().
        - Store service instances keyed by operation ID in an internal registry.
        - Provide get_service() for retrieving active services in route handlers.

    Attributes:
        _service_store (Dict[str, AbstractCaptureService]):
            Registry mapping operation IDs to service instances.
    """
    #Maintain singleton mapping of operation_id to service instances
    __SERVICE_STORE: dict[OperationId, AbstractCaptureService] = {}

    def __init__(self) -> None:
        """
        Initialize the internal service registry.
        """
        self._service_store: dict[OperationId, AbstractCaptureService] = {}
        self.logger = logging.getLogger(self.__class__.__name__)

    async def updateServiceStore(self, operation_id: OperationId, service: AbstractCaptureService) -> None:
        """
        Update the internal service registry with a new or modified service instance.

        Args:
            operation_id (OperationId): The unique ID of the operation.
            service (AbstractCaptureService): The service instance to register.

        Returns:
            None
        """
        self.__SERVICE_STORE[operation_id] = service

    async def loadService(self, service_cls: type[T], *args: Any, **kwargs: Any) -> tuple[GroupId, OperationId]:  # noqa: ANN401
        """
        Instantiate, start, and register a capture service.

        Args:
            service_cls (Type[T]): Capture service class to instantiate.
            *args: Positional args for the service constructor.
            **kwargs: Keyword args for the service constructor.

        Returns:
            Tuple[GroupId, OperationId]: (group_id, operation_id) returned by service.start().

        Raises:
            Exception: Propagates errors from instantiation or startup.

        Supported Service Types:
            - MultiRxMerService
            - MultiChannelEstimationService
            - MultiRxMer_Ofdm_Performance_1_Service

        """
        service: T = service_cls(*args, **kwargs)
        service.set_terminal_cleanup_callback(self.removeService)
        group_id, operation_id = await service.start()
        self._service_store[operation_id] = service
        return group_id, operation_id

    def getService(self, operation_id: OperationId) -> AbstractCaptureService:
        """
        Retrieve a previously loaded service by its operation ID.

        Args:
            operation_id (str): The ID returned by load_service().

        Returns:
            AbstractCaptureService: The associated service instance.

        Raises:
            KeyError: If no service exists for the given operation ID.
        """
        try:
            return self._service_store[operation_id]
        except KeyError as err:
            raise KeyError(f"No service loaded for operation_id '{operation_id}'") from err

    def getActiveServices(self) -> dict[OperationId, AbstractCaptureService]:
        """
        Retrieve all currently active services.

        Returns:
            Dict[OperationId, AbstractCaptureService]: Mapping of operation IDs to service instances.
        """
        self.logger.info(f'Retrieving active services. Current store: {self._service_store.keys()}')

        active_services: dict[OperationId, AbstractCaptureService] = {}

        for operation_id in self._service_store:
            self.logger.info(f"Active service: operation_id={operation_id}")
            if self._service_store[operation_id].status()["state"] == OperationState.RUNNING:
                self.logger.info(f"Service {operation_id} is running")
                active_services[operation_id] = self._service_store[operation_id]

        return active_services

    def removeService(self, operation_id: OperationId) -> None:
        """Remove a terminal service instance from the in-memory registry."""
        if operation_id in self._service_store:
            del self._service_store[operation_id]
