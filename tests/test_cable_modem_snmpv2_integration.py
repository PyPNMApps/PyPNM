from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025
import os

import pytest

from pypnm.config.system_config_settings import SystemConfigSettings
from pypnm.docsis.cable_modem import CableModem
from pypnm.lib.inet import Inet
from pypnm.lib.mac_address import MacAddress

# ---- Skip all tests unless explicitly enabled (prevents CI/network flakiness) ----
IT_ENABLED = os.getenv("PNM_CM_IT") == "1"
pytestmark = [
    pytest.mark.skipif(not IT_ENABLED, reason="Hardware integration disabled. Set PNM_CM_IT=1 to run."),
]

# ---- Guard: SNMPv2 must be enabled and SNMPv3 disabled for these tests ----
SNMPV2_OK = bool(SystemConfigSettings.snmp_enable) and not bool(SystemConfigSettings.snmp_v3_enable)
pytestmark.append(
    pytest.mark.skipif(not SNMPV2_OK, reason="SNMPv2 must be enabled and SNMPv3 disabled for this test suite.")
)

@pytest.fixture(scope="session")
def cm() -> CableModem:
    """
    Build a CableModem from SystemConfigSettings.
    Requires:
      - SystemConfigSettings.default_mac_address
      - SystemConfigSettings.default_ip_address
      - SystemConfigSettings.snmp_write_community (or read community if your class uses it)
    """
    mac = MacAddress(SystemConfigSettings.default_mac_address)
    inet = Inet(SystemConfigSettings.default_ip_address)
    # The CableModem ctor takes write_community; use the configured v2 write community.
    return CableModem(mac_address=mac, inet=inet, write_community=SystemConfigSettings.snmp_write_community)

def test_ping_reachable(cm: CableModem) -> None:
    assert cm.is_ping_reachable() is True

@pytest.mark.asyncio
async def test_snmp_reachable(cm: CableModem) -> None:
    assert await cm.is_snmp_reachable() is True

def test_same_inet_version_self_compare(cm: CableModem) -> None:
    # Compare CM's own address version with itself to sanity-check the Inet plumbing
    same = cm.same_inet_version(Inet(cm.get_inet_address))
    assert same is True
