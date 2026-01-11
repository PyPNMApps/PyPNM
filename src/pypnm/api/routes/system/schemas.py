# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

"""
Module: common_endpoint_classes.schema.sys

Defines request and response models for system SNMP operations (sysDescr and sysUpTime).
"""

from __future__ import annotations

from pypnm.api.routes.common.classes.common_endpoint_classes.schema.base_connect_request import (
    BaseDeviceConnectRequest,
)
from pypnm.api.routes.common.classes.common_endpoint_classes.snmp.schemas import (
    SnmpResponse,
)


class SysRequest(BaseDeviceConnectRequest):
    """
    Request model for system SNMP operations.

    Inherits from BaseDeviceConnectRequest to include connection parameters.
    """


class SysDescrResponse(SnmpResponse):
    """
    Response model for SNMP `sysDescr` query.

    The `results` field is a dictionary containing the `sysDescr` key with OID→description map.
    """


class SysUpTimeResponse(SnmpResponse):
    """
    Response model for SNMP `sysUpTime` query.

    The `results` field is a dictionary containing the `uptime` key with a human-readable string.
    """
