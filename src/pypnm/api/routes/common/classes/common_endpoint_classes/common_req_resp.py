# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field, ValidationInfo, field_validator

from pypnm.api.routes.advance.common.operation_state import OperationState
from pypnm.api.routes.common.classes.common_endpoint_classes.common.enum import (
    AnalysisType,
    OutputType,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_validation import (
    RequestListNormalizer,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.matplot.manager import ThemeType
from pypnm.lib.types import ChannelId, InetAddressStr, IPv4Str, IPv6Str, MacAddressStr

default_mac: MacAddressStr = SystemConfigSettings.default_mac_address()
default_ip: InetAddressStr = SystemConfigSettings.default_ip_address()
TFTP_IPV4_DEFAULT_DESC = "null uses system.json PnmBulkDataTransfer.tftp.ip_v4"
TFTP_IPV6_DEFAULT_DESC = "null uses system.json PnmBulkDataTransfer.tftp.ip_v6"
ERROR_TFTP_BLANK = "tftp.{field} must be null or a valid IP address"

class CommonOutput(BaseModel):
    type: OutputType = Field(default=OutputType.JSON, description="Desired output type for analysis results")

class TftpConfig(BaseModel):
    ipv4: IPv4Str | None = Field(..., description=f"TFTP server IPv4 address ({TFTP_IPV4_DEFAULT_DESC})")
    ipv6: IPv6Str | None = Field(..., description=f"TFTP server IPv6 address ({TFTP_IPV6_DEFAULT_DESC})")

    @field_validator("ipv4", "ipv6", mode="before")
    def _reject_blank(cls, v: object, info: ValidationInfo) -> object:
        if v is None:
            return v
        if isinstance(v, str) and v.strip() == "":
            raise ValueError(ERROR_TFTP_BLANK.format(field=info.field_name))
        return v

class PnmCaptureConfig(BaseModel):
    channel_ids: list[ChannelId] | None = Field(
        default=None,
        description="Optional channel id list for targeted captures (empty or missing means all channels).",
    )

    @field_validator("channel_ids", mode="after")
    def _dedupe_channel_ids(cls, v: list[ChannelId] | None) -> list[ChannelId] | None:
        return RequestListNormalizer.dedupe_preserve_order(v)

class PnmParameters(BaseModel):
    tftp: TftpConfig = Field(..., description="TFTP configuration")
    capture: PnmCaptureConfig = Field(default_factory=PnmCaptureConfig, description="Capture parameters")


class CableModemPnmConfig(BaseModel):
    mac_address: MacAddressStr    = Field(default=default_mac, description="MAC address of the cable modem")
    ip_address: InetAddressStr    = Field(default=default_ip, description="Inet address of the cable modem")
    pnm_parameters: PnmParameters = Field(description="PNM parameters such as TFTP server configuration")
    snmp: SNMPConfig              = Field(description="SNMP configuration")

    @field_validator("mac_address")
    def validate_mac(cls, v: str) -> MacAddressStr:
        try:
            return MacAddress(v).mac_address
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e


class CommonMatPlotUiConfig(BaseModel):
    theme: ThemeType = Field(default="dark", description="Matplotlib theme selection for plot rendering")

class CommonMatPlotConfigRequest(BaseModel):
    ui: CommonMatPlotUiConfig = Field(default=CommonMatPlotUiConfig(), description="Matplotlib UI configuration for plot generation")

class CommonFileSearchRequest(BaseModel):
    mac_address: MacAddressStr = Field(description="MAC address of the cable modem")

    @field_validator("mac_address")
    def validate_mac(cls, v: MacAddressStr) -> MacAddressStr:
        try:
            return MacAddress(v).to_mac_format(MacAddressFormat.COLON)
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e

class CommonRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration for basic PNM operations")


class CommonAnalysisType(BaseModel):
    type: int = Field(description="Analysis type to perform, implementation-specific integer value")

class CommonMultiAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: CommonAnalysisType     = Field(description="Analysis type to perform")


class CommonAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig = Field(description="Cable modem configuration")
    analysis: CommonAnalysisType     = Field(description="Analysis type or mode to perform")
    output: CommonOutput             = Field(description="Output type control: JSON or archive")


class CommonSingleCaptureAnalysisType(BaseModel):
    type: AnalysisType              = Field(default=AnalysisType.BASIC, description="Analysis type to perform")
    output: CommonOutput            = Field(description="Output format selection for single capture analysis")
    plot: CommonMatPlotConfigRequest = Field(description="Plot configuration for single capture analysis")


class CommonSingleCaptureAnalysisRequest(BaseModel):
    cable_modem: CableModemPnmConfig          = Field(description="Cable modem configuration")
    analysis: CommonSingleCaptureAnalysisType = Field(description="Single capture analysis configuration")


class CommonResponse(BaseModel):
    mac_address: MacAddressStr                                      = Field(default=default_mac, description="MAC address of the cable modem")
    status: ServiceStatusCode | OperationState | str | None = Field(default="success", description="Operation status code or state")
    message: str | None                                          = Field(default=None, description="Additional information or error details")

    @field_validator("mac_address")
    def validate_mac(cls, v: str) -> MacAddressStr:
        try:
            return MacAddress(v).mac_address
        except Exception as e:
            raise ValueError(f"Invalid MAC address: {v}, reason: ({e})") from e


class CommonAnalysisResponse(CommonResponse):
    """Basic analysis response model."""
    pass
