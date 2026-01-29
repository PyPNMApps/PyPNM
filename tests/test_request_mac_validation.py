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
