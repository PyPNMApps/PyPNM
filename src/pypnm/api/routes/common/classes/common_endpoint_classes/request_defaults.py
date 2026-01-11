# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    TftpConfig,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_snmp import (
    SNMPConfig,
)
from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.lib.inet import Inet

METHOD_TFTP = "tftp"
METHOD_HTTP = "http"
METHOD_HTTPS = "https"


class RequestDefaultsResolver:
    """
    Resolve request overrides with system.json defaults for PNM capture endpoints.
    """

    @staticmethod
    def resolve_tftp_servers(tftp: TftpConfig) -> tuple[Inet, Inet]:
        """
        Resolve TFTP server endpoints using request overrides and system defaults.
        """
        method = str(SystemConfigSettings.bulk_transfer_method()).strip().lower()
        if method != METHOD_TFTP:
            return (
                Inet(SystemConfigSettings.bulk_tftp_ip_v4()),
                Inet(SystemConfigSettings.bulk_tftp_ip_v6()),
            )
        ipv4 = tftp.ipv4 if tftp.ipv4 is not None else SystemConfigSettings.bulk_tftp_ip_v4()
        ipv6 = tftp.ipv6 if tftp.ipv6 is not None else SystemConfigSettings.bulk_tftp_ip_v6()
        return (Inet(ipv4), Inet(ipv6))

    @staticmethod
    def resolve_snmp_community(snmp: SNMPConfig) -> str:
        """
        Resolve SNMP write community using request overrides and system defaults.
        """
        community = snmp.snmp_v2c.community
        if community is None:
            return str(SystemConfigSettings.snmp_write_community())
        return str(community)


__all__ = [
    "RequestDefaultsResolver",
]
