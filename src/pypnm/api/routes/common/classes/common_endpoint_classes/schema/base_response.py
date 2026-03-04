
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from pydantic import BaseModel, Field, field_validator, model_validator

from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings as SCSC
from pypnm.docsis.data_type.sysDescr import SystemDescriptor, SystemDescriptorModel
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import MacAddressStr


class DeviceIdentity(BaseModel):
    """Canonical nested device identity for device-scoped API responses."""

    mac_address: MacAddressStr = Field(default_factory=SCSC.default_mac_address, description="MAC address of the cable modem, validated and normalized")
    system_description: SystemDescriptorModel = Field(
        default_factory=lambda: SystemDescriptor.empty().to_model(),
        description="Parsed sysDescr model for the target device (empty model when unavailable).",
    )

    @field_validator("mac_address", mode="before")
    def _normalize_mac(cls, v: object) -> str:
        if v is None:
            return MacAddress.null()
        try:
            return MacAddress(str(v)).to_mac_format(MacAddressFormat.COLON)
        except Exception:
            return str(v)


class BaseDeviceResponse(BaseModel):
    """
    Standard response model for all PNM FastAPI endpoints.

    Attributes:
        mac_address (str): Validated and normalized MAC address of the cable modem.
        status (ServiceStatusCode | OperationState | str): Result status of the operation.
        message (str, optional): Additional information or error details.
    """

    status: ServiceStatusCode | OperationState | str = Field(default="success", description="Status of the operation (e.g., 'success', 'error')")
    message: str | None = Field(default=None, description="Additional informational or error message")
    device: DeviceIdentity = Field(
        default_factory=DeviceIdentity,
        description="Canonical device identity block for the target cable modem.",
    )

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_identity_inputs(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        payload = dict(data)
        device = dict(payload.get("device") or {})
        if "mac_address" in payload and "mac_address" not in device:
            device["mac_address"] = payload.get("mac_address")
        system_description = payload.get("system_description")
        if (
            "system_description" in payload
            and "system_description" not in device
            and system_description is not None
        ):
            device["system_description"] = system_description
        if device:
            payload["device"] = device
        return payload
