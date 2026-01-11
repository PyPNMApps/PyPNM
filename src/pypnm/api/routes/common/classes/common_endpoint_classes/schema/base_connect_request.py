from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from ipaddress import ip_address

from pydantic import BaseModel, Field, field_validator

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
)
from pypnm.config.system_config_settings import SystemConfigSettings as SCSC
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import InetAddressStr, MacAddressStr


class CableModemOnlyConfig(BaseModel):
    """
    Encapsulates core cable modem fields without extra PNM metadata.
    """

    mac_address: MacAddressStr = Field(
        default=SCSC.default_mac_address(), description="MAC address of the cable modem"
    )
    ip_address: InetAddressStr = Field(
        default=SCSC.default_ip_address(), description="IP address of the cable modem"
    )
    snmp: SNMPConfig = Field(..., description="SNMP configuration block")

    @field_validator("mac_address", mode="before")
    def _normalize_mac(cls, v: str) -> str:
        try:
            return str(MacAddress(v))
        except Exception as e:
            raise ValueError(f"Invalid MAC address {v!r}: {e}") from e

    @field_validator("ip_address")
    def _validate_ip(cls, v: str) -> str:
        try:
            return str(ip_address(v))
        except ValueError:
            raise ValueError(f"Invalid IP address {v!r}") from None


class BaseDeviceConnectRequest(BaseModel):
    """
    Request model using nested cable_modem with only SNMP (no TFTP or extended PNM parameters).
    """

    cable_modem: CableModemOnlyConfig
