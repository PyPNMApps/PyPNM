from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia
from enum import IntEnum

from pydantic import BaseModel, Field

from pypnm.lib.types import InterfaceIndex
from pypnm.snmp.snmp_v2c import Snmp_v2c


class IfStackStatus(IntEnum):
    active = 1
    notInService = 2


class IfStackEntryModel(BaseModel):
    ifStackHigherLayer: InterfaceIndex = Field(..., description="Higher-layer IF-MIB ifIndex.")
    ifStackLowerLayer: InterfaceIndex = Field(..., description="Lower-layer IF-MIB ifIndex.")
    ifStackStatus: IfStackStatus | int | None = Field(default=None, description="ifStackStatus value.")


class IfStackEntry:
    @staticmethod
    def _as_int(value: str | None) -> int | None:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @classmethod
    async def get(cls, snmp: Snmp_v2c) -> list[IfStackEntryModel]:
        """Walk IF-MIB ifStackStatus rows and parse (higher, lower) ifIndex pairs."""
        rows: list[IfStackEntryModel] = []
        status_walk = await snmp.walk("ifStackStatus")
        if not status_walk:
            return rows

        base_oid = Snmp_v2c.resolve_oid("ifStackStatus")
        for varbind in status_walk:
            suffix = Snmp_v2c.oid_suffix_from_oid(oid=str(varbind[0]), base_oid=base_oid, expected_parts=2)
            if not suffix:
                continue

            parts = suffix.split(".")
            try:
                higher = InterfaceIndex(int(parts[0]))
                lower = InterfaceIndex(int(parts[1]))
            except (TypeError, ValueError):
                continue

            status_raw = cls._as_int(str(varbind[1]))
            status: IfStackStatus | int | None = IfStackStatus(status_raw) if status_raw in {1, 2} else status_raw

            rows.append(
                IfStackEntryModel(
                    ifStackHigherLayer=higher,
                    ifStackLowerLayer=lower,
                    ifStackStatus=status,
                )
            )

        return rows
