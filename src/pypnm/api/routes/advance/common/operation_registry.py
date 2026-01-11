# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import threading
from typing import Protocol

from pypnm.lib.types import OperationId


class OperationServiceProtocol(Protocol):
    def stop(self, operation_id: OperationId) -> None: ...

    def status(self, operation_id: OperationId) -> dict[str, object]: ...


class OperationRegistry:
    """
    In-memory registry mapping operation IDs to running capture services.
    """

    _lock = threading.Lock()
    _services: dict[OperationId, OperationServiceProtocol] = {}

    @classmethod
    def register(
        cls, operation_id: OperationId, service: OperationServiceProtocol
    ) -> None:
        logger = logging.getLogger(cls.__name__)
        with cls._lock:
            cls._services[operation_id] = service
        logger.debug("Registered operation service for operation_id=%s", operation_id)

    @classmethod
    def get(cls, operation_id: OperationId) -> OperationServiceProtocol | None:
        with cls._lock:
            return cls._services.get(operation_id)

    @classmethod
    def unregister(cls, operation_id: OperationId) -> None:
        logger = logging.getLogger(cls.__name__)
        with cls._lock:
            removed = cls._services.pop(operation_id, None)
        if removed is not None:
            logger.debug(
                "Unregistered operation service for operation_id=%s", operation_id
            )


__all__ = ["OperationRegistry", "OperationServiceProtocol"]
