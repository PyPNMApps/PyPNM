
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from pydantic import BaseModel, Field, field_validator

from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings as SCSC
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import MacAddressStr


class BaseDeviceResponse(BaseModel):
    """
    Standard response model for all PNM FastAPI endpoints.

    Attributes:
        mac_address (str): Validated and normalized MAC address of the cable modem.
        status (ServiceStatusCode | OperationState | str): Result status of the operation.
        message (str, optional): Additional information or error details.
    """

    mac_address: MacAddressStr                              = Field(default_factory=SCSC.default_mac_address, description="MAC address of the cable modem, validated and normalized")
    status: ServiceStatusCode | OperationState | str   = Field(default="success", description="Status of the operation (e.g., 'success', 'error')")
    message: str | None                                  = Field(default=None, description="Additional informational or error message")

    @field_validator("mac_address", mode="before")
    def _normalize_mac(cls, v: object) -> str:
        """
        Normalize and validate a raw MAC address string before assignment.

        Args:
            v (str): Raw MAC address input.

        Returns:
            str: Canonical MAC address (e.g., "00:11:22:33:44:55").

        Raises:
            ValueError: If the provided MAC is invalid.
        """
        if v is None:
            return MacAddress.null()
        try:
            return MacAddress(str(v)).to_mac_format(MacAddressFormat.COLON)
        except Exception:
            return str(v)
