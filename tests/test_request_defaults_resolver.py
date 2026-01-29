# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest
from pydantic import ValidationError

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    PnmCaptureConfig,
    TftpConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.request_defaults import (
    RequestDefaultsResolver,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
    SNMPv2c,
)
from pypnm.api.routes.common.service.status_codes import ServiceStatusCode
from pypnm.api.routes.common.classes.common_endpoint_classes.schemas import (
    PnmSingleCaptureRequest,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.inet import Inet


def test_tftp_ipv4_blank_is_rejected() -> None:
    with pytest.raises(ValidationError, match="tftp\\.ipv4 must be null or a valid IP address"):
        TftpConfig(ipv4="", ipv6=None)


def test_tftp_ipv6_blank_is_rejected() -> None:
    with pytest.raises(ValidationError, match="tftp\\.ipv6 must be null or a valid IP address"):
        TftpConfig(ipv4=None, ipv6="")


def test_snmp_v2c_blank_is_rejected() -> None:
    with pytest.raises(ValidationError, match="SNMPv2c\\.community must not be blank"):
        SNMPv2c(community="")


def test_resolver_defaults_used_for_null_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SystemConfigSettings, "bulk_transfer_method", staticmethod(lambda: "tftp"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v4", staticmethod(lambda: "192.168.0.10"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v6", staticmethod(lambda: "2001:db8::10"))
    monkeypatch.setattr(SystemConfigSettings, "snmp_write_community", staticmethod(lambda: "private"))

    tftp = TftpConfig(ipv4=None, ipv6=None)
    snmp = SNMPConfig(snmp_v2c=SNMPv2c(community=None))

    tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(tftp)
    community = RequestDefaultsResolver.resolve_snmp_community(snmp)

    assert tftp_servers == (Inet("192.168.0.10"), Inet("2001:db8::10"))
    assert community == "private"


def test_resolver_ignores_request_when_not_tftp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SystemConfigSettings, "bulk_transfer_method", staticmethod(lambda: "http"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v4", staticmethod(lambda: "192.168.0.10"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v6", staticmethod(lambda: "2001:db8::10"))

    tftp = TftpConfig(ipv4="192.168.0.20", ipv6="2001:db8::20")
    tftp_servers = RequestDefaultsResolver.resolve_tftp_servers(tftp)

    assert tftp_servers == (Inet("192.168.0.10"), Inet("2001:db8::10"))


def test_resolver_checked_rejects_invalid_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SystemConfigSettings, "bulk_transfer_method", staticmethod(lambda: "tftp"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v4", staticmethod(lambda: "192.168.0.10"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v6", staticmethod(lambda: "2001:db8::10"))

    tftp = TftpConfig(ipv4="192.168.0.10a", ipv6="2001:db8::20")
    status, _, servers = RequestDefaultsResolver.resolve_tftp_servers_checked(tftp)

    assert status == ServiceStatusCode.INVALID_INET_ADDRESS_FORMAT
    assert servers is None


def test_resolver_checked_rejects_invalid_ipv6(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SystemConfigSettings, "bulk_transfer_method", staticmethod(lambda: "tftp"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v4", staticmethod(lambda: "192.168.0.10"))
    monkeypatch.setattr(SystemConfigSettings, "bulk_tftp_ip_v6", staticmethod(lambda: "2001:db8::10"))

    tftp = TftpConfig(ipv4="192.168.0.20", ipv6="2001:db8::10g")
    status, _, servers = RequestDefaultsResolver.resolve_tftp_servers_checked(tftp)

    assert status == ServiceStatusCode.INVALID_INET_ADDRESS_FORMAT
    assert servers is None


def test_rxmer_request_rejects_blank_tftp_ipv4() -> None:
    payload = {
        "cable_modem": {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.0.100",
            "pnm_parameters": {
                "tftp": {
                    "ipv4": "",
                    "ipv6": None,
                },
                "capture": {
                    "channel_ids": [],
                },
            },
            "snmp": {
                "snmpV2C": {
                    "community": None,
                },
            },
        },
        "analysis": {
            "type": "basic",
            "output": {
                "type": "json",
            },
            "plot": {
                "ui": {
                    "theme": "dark",
                },
            },
        },
    }
    with pytest.raises(ValidationError):
        PnmSingleCaptureRequest.model_validate(payload)


def test_channel_ids_dedupe_preserves_order() -> None:
    capture = PnmCaptureConfig(channel_ids=[193, 193, 194])
    assert capture.channel_ids == [193, 194]
