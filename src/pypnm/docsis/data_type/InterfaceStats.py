from __future__ import annotations

from collections.abc import Callable

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import IntEnum

from pydantic import BaseModel

from pypnm.snmp.modules import DocsisIfType
from pypnm.snmp.snmp_v2c import Snmp_v2c


class IfAdminStatus(IntEnum):
    up = 1
    down = 2
    testing = 3


class IfOperStatus(IntEnum):
    up = 1
    down = 2
    testing = 3


class IfEntry(BaseModel):
    ifIndex: int
    ifDescr: str
    ifType: DocsisIfType
    ifMtu: int
    ifSpeed: int
    ifPhysAddress: str
    ifAdminStatus: IfAdminStatus
    ifOperStatus: IfOperStatus
    ifLastChange: int
    ifInOctets: int
    ifInUcastPkts: int
    ifInNUcastPkts: int | None = None
    ifInDiscards: int
    ifInErrors: int
    ifInUnknownProtos: int
    ifOutOctets: int
    ifOutUcastPkts: int
    ifOutNUcastPkts: int | None = None
    ifOutDiscards: int
    ifOutErrors: int
    ifOutQLen: int | None = None
    ifSpecific: str | None = None


class IfXEntry(BaseModel):
    ifName: str
    ifInMulticastPkts: int
    ifInBroadcastPkts: int
    ifOutMulticastPkts: int
    ifOutBroadcastPkts: int
    ifHCInOctets: int
    ifHCInUcastPkts: int
    ifHCInMulticastPkts: int
    ifHCInBroadcastPkts: int
    ifHCOutOctets: int
    ifHCOutUcastPkts: int
    ifHCOutMulticastPkts: int
    ifHCOutBroadcastPkts: int
    ifLinkUpDownTrapEnable: int
    ifHighSpeed: int
    ifPromiscuousMode: bool
    ifConnectorPresent: bool
    ifAlias: str
    ifCounterDiscontinuityTime: int


class InterfaceStats(BaseModel):
    ifEntry: IfEntry
    ifXEntry: IfXEntry | None = None

    @classmethod
    async def from_snmp(
        cls, snmp: Snmp_v2c, if_type_filter: DocsisIfType
    ) -> list[InterfaceStats]:
        stats_list = []

        for if_index in await snmp.walk("ifIndex"):
            index = Snmp_v2c.get_oid_index(str(if_index[0]))
            if index is None:
                # skip malformed oid index results
                continue

            if_type = await snmp.get(f"ifType.{index}")
            type_val = Snmp_v2c.get_result_value(if_type)

            if type_val is None or int(type_val) != if_type_filter:
                continue

            def safe_cast(
                value: str, cast: Callable
            ) -> int | float | str | bool | None:
                try:
                    return cast(value)
                except (ValueError, TypeError):
                    return None

            async def fetch(
                field: str, cast: Callable | None = None, index: str | int = index
            ) -> None | int | float | str | bool:
                """Fetch and optionally cast an SNMP field value for a given index."""
                raw = await snmp.get(f"{field}.{index}")
                val = Snmp_v2c.get_result_value(raw)

                if val is None or val == "":
                    return None

                if cast:
                    return safe_cast(val, cast)

                # Auto-detect numeric (int), float, bool, or fallback to str
                val = val.strip()
                if val.isdigit():
                    return int(val)
                if val.lower() in ("true", "false"):
                    return val.lower() == "true"
                try:
                    return float(val)
                except ValueError:
                    return val

            entry = IfEntry(
                ifIndex=index,
                ifDescr=await fetch("ifDescr", str),
                ifType=DocsisIfType(int(type_val)),
                ifMtu=await fetch("ifMtu", int),
                ifSpeed=await fetch("ifSpeed", int),
                ifPhysAddress=str(await fetch("ifPhysAddress", str) or ""),
                ifAdminStatus=IfAdminStatus(await fetch("ifAdminStatus", int)),
                ifOperStatus=IfOperStatus(await fetch("ifOperStatus", int)),
                ifLastChange=await fetch("ifLastChange", int),
                ifInOctets=await fetch("ifInOctets", int),
                ifInUcastPkts=await fetch("ifInUcastPkts", int),
                ifInNUcastPkts=await fetch("ifInNUcastPkts", int),
                ifInDiscards=await fetch("ifInDiscards", int),
                ifInErrors=await fetch("ifInErrors", int),
                ifInUnknownProtos=await fetch("ifInUnknownProtos", int),
                ifOutOctets=await fetch("ifOutOctets", int),
                ifOutUcastPkts=await fetch("ifOutUcastPkts", int),
                ifOutNUcastPkts=await fetch("ifOutNUcastPkts", int),
                ifOutDiscards=await fetch("ifOutDiscards", int),
                ifOutErrors=await fetch("ifOutErrors", int),
                ifOutQLen=await fetch("ifOutQLen", int),
                ifSpecific=await fetch("ifSpecific", str),
            )

            try:
                xentry = IfXEntry(
                    **{
                        field: Snmp_v2c.get_result_value(
                            await snmp.get(f"{field}.{index}")
                        )
                        for field in IfXEntry.__annotations__
                    }
                )
            except Exception:
                xentry = None

            stats_list.append(cls(ifEntry=entry, ifXEntry=xentry))

        return stats_list
