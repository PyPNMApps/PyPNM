## Agent Review Bundle Summary
- Goal: Allow invalid MAC/INET inputs to reach precheck and return consistent error responses.
- Changes: Relax request/response MAC and IP validators; add tests for invalid MAC/IP pass-through.
- Files: src/pypnm/api/routes/common/classes/common_endpoint_classes/common_req_resp.py; src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_connect_request.py; src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_response.py; tests/test_request_mac_validation.py
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: repo drift); pytest -q
- Notes: ruff format --check . reports many files would be reformatted; pytest skips hardware integration tests (PNM_CM_IT).

# FILE: src/pypnm/api/routes/common/classes/common_endpoint_classes/common_req_resp.py
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

    @field_validator("mac_address", mode="before")
    def validate_mac(cls, v: object) -> MacAddressStr:
        if v is None:
            return default_mac
        try:
            return MacAddress(str(v)).mac_address
        except Exception:
            return MacAddressStr(str(v))


class CommonMatPlotUiConfig(BaseModel):
    theme: ThemeType = Field(default="dark", description="Matplotlib theme selection for plot rendering")

class CommonMatPlotConfigRequest(BaseModel):
    ui: CommonMatPlotUiConfig = Field(default=CommonMatPlotUiConfig(), description="Matplotlib UI configuration for plot generation")

class CommonFileSearchRequest(BaseModel):
    mac_address: MacAddressStr = Field(description="MAC address of the cable modem")

    @field_validator("mac_address", mode="before")
    def validate_mac(cls, v: object) -> MacAddressStr:
        if v is None:
            return default_mac
        try:
            return MacAddress(str(v)).to_mac_format(MacAddressFormat.COLON)
        except Exception:
            return MacAddressStr(str(v))

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

    @field_validator("mac_address", mode="before")
    def validate_mac(cls, v: object) -> MacAddressStr:
        if v is None:
            return default_mac
        try:
            return MacAddress(str(v)).mac_address
        except Exception:
            return MacAddressStr(str(v))


class CommonAnalysisResponse(CommonResponse):
    """Basic analysis response model."""
    pass

# FILE: src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_connect_request.py

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
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
    mac_address: MacAddressStr = Field(default=SCSC.default_mac_address(),description="MAC address of the cable modem")
    ip_address: InetAddressStr = Field(default=SCSC.default_ip_address(), description="IP address of the cable modem")
    snmp: SNMPConfig = Field(...,description="SNMP configuration block")

    @field_validator("mac_address", mode="before")
    def _normalize_mac(cls, v: object) -> str:
        if v is None:
            return str(SCSC.default_mac_address())
        try:
            return str(MacAddress(str(v)))
        except Exception:
            return str(v)

    @field_validator("ip_address", mode="before")
    def _validate_ip(cls, v: object) -> str:
        if v is None:
            return str(SCSC.default_ip_address())
        try:
            return str(ip_address(str(v)))
        except ValueError:
            return str(v)

class BaseDeviceConnectRequest(BaseModel):
    """
    Request model using nested cable_modem with only SNMP (no TFTP or extended PNM parameters).
    """
    cable_modem: CableModemOnlyConfig

# FILE: src/pypnm/api/routes/common/classes/common_endpoint_classes/schema/base_response.py

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

# FILE: tests/test_request_mac_validation.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CableModemPnmConfig,
    PnmParameters,
    TftpConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    CableModemOnlyConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
    SNMPv2c,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode


def test_cable_modem_pnm_config_allows_invalid_mac() -> None:
    config = CableModemPnmConfig(
        mac_address="00:50:F1:12:03:60a",
        ip_address="192.168.0.1",
        pnm_parameters=PnmParameters(
            tftp=TftpConfig(ipv4="192.168.0.100", ipv6=None),
        ),
        snmp=SNMPConfig(snmp_v2c=SNMPv2c(community="public")),
    )

    assert config.mac_address == "00:50:F1:12:03:60a"


def test_cable_modem_only_config_allows_invalid_ip() -> None:
    config = CableModemOnlyConfig(
        mac_address="aa:bb:cc:dd:ee:ff",
        ip_address="172.19.32.171a",
        snmp=SNMPConfig(snmp_v2c=SNMPv2c(community="public")),
    )

    assert config.ip_address == "172.19.32.171a"


def test_snmp_response_allows_invalid_mac() -> None:
    response = SnmpResponse(
        mac_address="00:50:F1:12:03:60a",
        status=ServiceStatusCode.INVALID_MAC_ADDRESS_FORMAT,
        message="Invalid MAC address format: 00:50:F1:12:03:60a",
    )

    assert response.mac_address == "00:50:F1:12:03:60a"
