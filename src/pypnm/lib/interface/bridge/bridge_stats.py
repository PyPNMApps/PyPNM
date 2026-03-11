from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia
from enum import IntEnum

from pydantic import BaseModel, Field

from pypnm.lib.interface.IfStackEntry import IfStackEntry, IfStackEntryModel
from pypnm.lib.types import (
    BridgeAddressStr,
    InterfaceIndex,
    InterfaceIndexStr,
    MacAddressStr,
    PortId,
)
from pypnm.snmp.snmp_v2c import Snmp_v2c


class Dot1dBaseType(IntEnum):
    unknown = 1
    transparent_only = 2
    sourceroute_only = 3
    srt = 4


class Dot1dTpFdbStatus(IntEnum):
    other = 1
    invalid = 2
    learned = 3
    self = 4
    mgmt = 5


class Dot1dBaseModel(BaseModel):
    dot1dBaseBridgeAddress: BridgeAddressStr | None = Field(default=None, description="Bridge MAC address from dot1dBaseBridgeAddress.0.")
    dot1dBaseNumPorts: int | None = Field(default=None, description="Number of bridge ports from dot1dBaseNumPorts.0.")
    dot1dBaseType: Dot1dBaseType | None = Field(default=None, description="Bridge type enum from dot1dBaseType.0.")


class Dot1dBasePortEntryModel(BaseModel):
    dot1dBasePort: PortId = Field(..., description="Bridge port number from dot1dBasePort.")
    dot1dBasePortIfIndex: InterfaceIndex = Field(..., description="Mapped IF-MIB ifIndex from dot1dBasePortIfIndex.")
    dot1dBasePortCircuit: str | None = Field(default=None, description="Port circuit reference OID from dot1dBasePortCircuit.")
    dot1dBasePortDelayExceededDiscards: int | None = Field(default=None, description="Discard counter from dot1dBasePortDelayExceededDiscards.")
    dot1dBasePortMtuExceededDiscards: int | None = Field(default=None, description="Discard counter from dot1dBasePortMtuExceededDiscards.")


class Dot1dTpPortEntryModel(BaseModel):
    dot1dTpPort: PortId = Field(..., description="Transparent bridge forwarding database port.")
    dot1dTpPortMaxInfo: int | None = Field(default=None, description="Maximum frame size on the TP port.")
    dot1dTpPortInFrames: int | None = Field(default=None, description="Inbound frame counter on the TP port.")
    dot1dTpPortOutFrames: int | None = Field(default=None, description="Outbound frame counter on the TP port.")
    dot1dTpPortInDiscards: int | None = Field(default=None, description="Inbound discard counter on the TP port.")


class Dot1dTpFdbEntryModel(BaseModel):
    dot1dTpFdbAddress: MacAddressStr = Field(..., description="Forwarding database MAC address key.")
    dot1dTpFdbPort: PortId | None = Field(default=None, description="Port associated with FDB MAC entry.")
    dot1dTpFdbStatus: Dot1dTpFdbStatus | None = Field(default=None, description="FDB entry status enum.")


class BridgeByIfIndexModel(BaseModel):
    ifType: int | None = Field(default=None, description="IF-MIB ifType value for this ifIndex.")
    ifDescription: str | None = Field(default=None, description="IF-MIB ifDescr value for this ifIndex.")
    ifName: str | None = Field(default=None, description="IF-MIB ifName value for this ifIndex.")
    dot1dBase: list[Dot1dBaseModel] = Field(default_factory=list, description="BRIDGE-MIB dot1dBase scalar section.")
    dot1dBasePortEntry: list[Dot1dBasePortEntryModel] = Field(default_factory=list, description="dot1dBasePortEntry rows mapped to this ifIndex.")
    dot1dTpPortEntry: list[Dot1dTpPortEntryModel] = Field(default_factory=list, description="dot1dTpPortEntry rows mapped through bridge port to this ifIndex.")
    dot1dTpFdbEntry: list[Dot1dTpFdbEntryModel] = Field(default_factory=list, description="dot1dTpFdbEntry rows mapped through bridge port to this ifIndex.")
    ifStackEntry: list[IfStackEntryModel] = Field(default_factory=list, description="IF-MIB ifStack entries associated with this ifIndex.")


class BridgeSchema(BaseModel):
    ifIndexes: dict[InterfaceIndexStr, BridgeByIfIndexModel] = Field(
        default_factory=dict,
        description="Bridge rows grouped by IF-MIB ifIndex using dot1dBasePortIfIndex mapping.",
    )


class BridgeStats:
    @staticmethod
    def _as_int(value: str | None) -> int | None:
        """Best-effort cast from SNMP scalar string to int."""
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @classmethod
    async def get_dot1d_base(cls, snmp: Snmp_v2c) -> Dot1dBaseModel | None:
        """Fetch BRIDGE-MIB dot1dBase scalar values."""
        base_bridge_addr = Snmp_v2c.get_result_value(await snmp.get("dot1dBaseBridgeAddress.0"))
        base_num_ports = cls._as_int(Snmp_v2c.get_result_value(await snmp.get("dot1dBaseNumPorts.0")))
        base_type_raw = cls._as_int(Snmp_v2c.get_result_value(await snmp.get("dot1dBaseType.0")))
        base_type = Dot1dBaseType(base_type_raw) if base_type_raw in {1, 2, 3, 4} else None

        if base_bridge_addr is None and base_num_ports is None and base_type is None:
            return None

        return Dot1dBaseModel(
            dot1dBaseBridgeAddress=base_bridge_addr,
            dot1dBaseNumPorts=base_num_ports,
            dot1dBaseType=base_type,
        )

    @classmethod
    async def get_dot1d_base_port_entries(cls, snmp: Snmp_v2c) -> list[Dot1dBasePortEntryModel]:
        """Walk and build dot1dBasePortEntry rows."""
        rows: list[Dot1dBasePortEntryModel] = []
        index_walk = await snmp.walk("dot1dBasePortIfIndex")
        if not index_walk:
            return rows

        for varbind in index_walk:
            idx = Snmp_v2c.get_oid_index(str(varbind[0]))
            if idx is None:
                continue

            port = cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dBasePort.{idx}")))
            port_ifindex = cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dBasePortIfIndex.{idx}")))
            if port is None or port_ifindex is None:
                continue

            rows.append(
                Dot1dBasePortEntryModel(
                    dot1dBasePort=PortId(port),
                    dot1dBasePortIfIndex=InterfaceIndex(port_ifindex),
                    dot1dBasePortCircuit=Snmp_v2c.get_result_value(await snmp.get(f"dot1dBasePortCircuit.{idx}")),
                    dot1dBasePortDelayExceededDiscards=cls._as_int(
                        Snmp_v2c.get_result_value(await snmp.get(f"dot1dBasePortDelayExceededDiscards.{idx}"))
                    ),
                    dot1dBasePortMtuExceededDiscards=cls._as_int(
                        Snmp_v2c.get_result_value(await snmp.get(f"dot1dBasePortMtuExceededDiscards.{idx}"))
                    ),
                )
            )

        return rows

    @classmethod
    async def get_dot1d_tp_port_entries(cls, snmp: Snmp_v2c) -> list[Dot1dTpPortEntryModel]:
        """Walk and build dot1dTpPortEntry rows."""
        rows: list[Dot1dTpPortEntryModel] = []
        index_walk = await snmp.walk("dot1dTpPort")
        if not index_walk:
            return rows

        for varbind in index_walk:
            idx = Snmp_v2c.get_oid_index(str(varbind[0]))
            if idx is None:
                continue

            tp_port = cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpPort.{idx}")))
            if tp_port is None:
                continue

            rows.append(
                Dot1dTpPortEntryModel(
                    dot1dTpPort=PortId(tp_port),
                    dot1dTpPortMaxInfo=cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpPortMaxInfo.{idx}"))),
                    dot1dTpPortInFrames=cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpPortInFrames.{idx}"))),
                    dot1dTpPortOutFrames=cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpPortOutFrames.{idx}"))),
                    dot1dTpPortInDiscards=cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpPortInDiscards.{idx}"))),
                )
            )

        return rows

    @classmethod
    async def get_dot1d_tp_fdb_entries(cls, snmp: Snmp_v2c) -> list[Dot1dTpFdbEntryModel]:
        """Walk and build dot1dTpFdbEntry rows keyed by MAC suffix indices."""
        rows: list[Dot1dTpFdbEntryModel] = []
        address_walk = await snmp.walk("dot1dTpFdbAddress")
        if not address_walk:
            return rows

        base_oid = Snmp_v2c.resolve_oid("dot1dTpFdbAddress")
        for varbind in address_walk:
            oid = str(varbind[0])
            mac = Snmp_v2c.as_mac_from_oid(oid=oid, base_oid=base_oid)
            suffix = Snmp_v2c.oid_suffix_from_oid(oid=oid, base_oid=base_oid, expected_parts=6)
            if not mac or not suffix:
                continue

            port_raw = Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpFdbPort.{suffix}"))
            status_raw = Snmp_v2c.get_result_value(await snmp.get(f"dot1dTpFdbStatus.{suffix}"))

            status_int = cls._as_int(status_raw)
            status = Dot1dTpFdbStatus(status_int) if status_int in {1, 2, 3, 4, 5} else None

            rows.append(
                Dot1dTpFdbEntryModel(
                    dot1dTpFdbAddress=mac,
                    dot1dTpFdbPort=PortId(port_val) if (port_val := cls._as_int(port_raw)) is not None else None,
                    dot1dTpFdbStatus=status,
                )
            )

        return rows

    @classmethod
    async def get_if_metadata(cls, snmp: Snmp_v2c, ifindex: InterfaceIndex) -> tuple[int | None, str | None, str | None]:
        """Fetch IF-MIB metadata for a single interface index."""
        if_key = int(ifindex)
        if_type = cls._as_int(Snmp_v2c.get_result_value(await snmp.get(f"ifType.{if_key}")))
        if_description = Snmp_v2c.get_result_value(await snmp.get(f"ifDescr.{if_key}"))
        if_name = Snmp_v2c.get_result_value(await snmp.get(f"ifName.{if_key}"))
        return if_type, if_description, if_name

    @classmethod
    async def get(cls, snmp: Snmp_v2c) -> BridgeSchema | None:
        """Collect BRIDGE-MIB sections into a grouped bridge schema object."""
        base = await cls.get_dot1d_base(snmp)
        base_ports = await cls.get_dot1d_base_port_entries(snmp)
        tp_ports = await cls.get_dot1d_tp_port_entries(snmp)
        fdb = await cls.get_dot1d_tp_fdb_entries(snmp)
        if_stack = await IfStackEntry.get(snmp)

        if not base and not base_ports and not tp_ports and not fdb and not if_stack:
            return None

        port_to_ifindex: dict[int, InterfaceIndex] = {}
        grouped: dict[int, BridgeByIfIndexModel] = {}
        if_metadata_cache: dict[int, tuple[int | None, str | None, str | None]] = {}

        async def ensure_group(if_key: int) -> BridgeByIfIndexModel | None:
            if if_key not in if_metadata_cache:
                if_metadata_cache[if_key] = await cls.get_if_metadata(snmp, InterfaceIndex(if_key))
            if if_metadata_cache[if_key][0] is None:
                return None
            if if_key not in grouped:
                grouped[if_key] = BridgeByIfIndexModel(dot1dBase=[base] if base else [])
            grouped[if_key].ifType = if_metadata_cache[if_key][0]
            grouped[if_key].ifDescription = if_metadata_cache[if_key][1]
            grouped[if_key].ifName = if_metadata_cache[if_key][2]
            return grouped[if_key]

        for entry in base_ports:
            bridge_port = int(entry.dot1dBasePort)
            ifindex = InterfaceIndex(int(entry.dot1dBasePortIfIndex))
            if_key = int(ifindex)
            group = await ensure_group(if_key)
            if group is None:
                continue
            port_to_ifindex[bridge_port] = ifindex
            group.dot1dBasePortEntry.append(entry)

        for entry in tp_ports:
            ifindex = port_to_ifindex.get(int(entry.dot1dTpPort))
            if ifindex is None:
                continue
            group = await ensure_group(int(ifindex))
            if group is None:
                continue
            group.dot1dTpPortEntry.append(entry)

        for entry in fdb:
            if entry.dot1dTpFdbPort is None:
                continue
            ifindex = port_to_ifindex.get(int(entry.dot1dTpFdbPort))
            if ifindex is None:
                continue
            group = await ensure_group(int(ifindex))
            if group is None:
                continue
            group.dot1dTpFdbEntry.append(entry)

        for entry in if_stack:
            higher = int(entry.ifStackHigherLayer)
            lower = int(entry.ifStackLowerLayer)
            higher_group = await ensure_group(higher)
            if higher_group is not None:
                higher_group.ifStackEntry.append(entry)
            lower_group = await ensure_group(lower)
            if lower_group is not None:
                lower_group.ifStackEntry.append(entry)

        if not grouped:
            return None

        ifindexes: dict[InterfaceIndexStr, BridgeByIfIndexModel] = {
            InterfaceIndexStr(str(k)): grouped[k] for k in sorted(grouped.keys())
        }

        return BridgeSchema(
            ifIndexes=ifindexes,
        )
