# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from types import MethodType

import pytest
from pysnmp.hlapi.v3arch.asyncio import ObjectType

from pypnm.lib.inet import Inet
from pypnm.snmp.snmp_v2c import Snmp_v2c


@pytest.mark.asyncio
async def test_set_with_retry_retries_on_resource_unavailable() -> None:
    snmp = Snmp_v2c(host=Inet("127.0.0.1"))
    calls: list[int] = []

    async def fake_set_once(
        self: Snmp_v2c,
        oid: str,
        value: str | int,
        value_type: Snmp_v2c.SnmpValueType,
    ) -> tuple[list[ObjectType] | None, str | None]:
        calls.append(1)
        if len(calls) < 3:
            return None, "SNMP error resourceUnavailable at index 1"
        return [], None

    snmp._set_once = MethodType(fake_set_once, snmp)

    response = await snmp.set_with_retry(
        oid="1.2.3.4.5",
        value=1,
        value_type=int,
        retries=3,
        base_delay_seconds=0.0,
        backoff=1.0,
    )

    assert response == []
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_set_with_retry_does_not_retry_on_other_errors() -> None:
    snmp = Snmp_v2c(host=Inet("127.0.0.1"))
    calls: list[int] = []

    async def fake_set_once(
        self: Snmp_v2c,
        oid: str,
        value: str | int,
        value_type: Snmp_v2c.SnmpValueType,
    ) -> tuple[list[ObjectType] | None, str | None]:
        calls.append(1)
        return None, "SNMP error undoFailed at index 1"

    snmp._set_once = MethodType(fake_set_once, snmp)

    response = await snmp.set_with_retry(
        oid="1.2.3.4.5",
        value=1,
        value_type=int,
        retries=3,
        base_delay_seconds=0.0,
        backoff=1.0,
    )

    assert response is None
    assert len(calls) == 1
