# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import (
    INVALID_CHANNEL_ID,
    KHZ,
    DocsIf31CmDsOfdmChanIndicator,
)
from pypnm.lib.types import ChannelId, FrequencyHz
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIf31CmDsOfdmChanEntry(BaseModel):
    """
    DOCSIS 3.1 CM Downstream OFDM Channel attributes (docsIf31CmDsOfdmChanTable).

    Notes
    -----
    - All values are retrieved via symbolic OIDs (no compiled OIDs).
    - Presence of fields depends on device/MIB support.
    """
    docsIf31CmDsOfdmChanChannelId:                ChannelId = INVALID_CHANNEL_ID
    docsIf31CmDsOfdmChanChanIndicator:            DocsIf31CmDsOfdmChanIndicator | None = None
    docsIf31CmDsOfdmChanSubcarrierZeroFreq:       FrequencyHz | None = None
    docsIf31CmDsOfdmChanFirstActiveSubcarrierNum: int | None = None
    docsIf31CmDsOfdmChanLastActiveSubcarrierNum:  int | None = None
    docsIf31CmDsOfdmChanNumActiveSubcarriers:     int | None = None
    docsIf31CmDsOfdmChanSubcarrierSpacing:        int | None = None
    docsIf31CmDsOfdmChanCyclicPrefix:             int | None = None
    docsIf31CmDsOfdmChanRollOffPeriod:            int | None = None
    docsIf31CmDsOfdmChanPlcFreq:                  FrequencyHz | None = None
    docsIf31CmDsOfdmChanNumPilots:                int | None = None
    docsIf31CmDsOfdmChanTimeInterleaverDepth:     int | None = None
    docsIf31CmDsOfdmChanPlcTotalCodewords:        int | None = None
    docsIf31CmDsOfdmChanPlcUnreliableCodewords:   int | None = None
    docsIf31CmDsOfdmChanNcpTotalFields:           int | None = None
    docsIf31CmDsOfdmChanNcpFieldCrcFailures:      int | None = None


class DocsIf31CmDsOfdmChanChannelEntry(BaseModel):
    """
    Container for a single downstream OFDM channel record retrieved via SNMP.

    Attributes
    ----------
    index : int
        Table index used to query SNMP (instance suffix).
    channel_id : int
        Mirrored from ``docsIf31CmDsOfdmChanChannelId``; 0 if absent.
    entry : DocsIf31CmDsOfdmChanEntry
        Populated OFDM channel attributes for this index.
    """
    index: int
    channel_id: int
    entry: DocsIf31CmDsOfdmChanEntry

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIf31CmDsOfdmChanChannelEntry:
        logger = logging.getLogger(cls.__name__)

        def safe_cast(value: str, cast: Callable) -> int | float | str | bool | None:
            try:
                return cast(value)
            except Exception:
                return None

        async def fetch(field: str, cast: Callable | None = None) -> None | int | float | str | bool:
            try:
                raw = await snmp.get(f"{field}.{index}")
                val = Snmp_v2c.get_result_value(raw)

                if val is None or val == "":
                    return None

                if cast is not None:
                    return safe_cast(val, cast)

                s = str(val).strip()
                if s.isdigit():
                    return int(s)
                if s.lower() in ("true", "false"):
                    return s.lower() == "true"
                try:
                    return float(s)
                except ValueError:
                    return s
            except Exception as e:
                logger.warning(f"Failed to fetch {field}.{index}: {e}")
                return None

        entry = DocsIf31CmDsOfdmChanEntry(
            docsIf31CmDsOfdmChanChannelId                 = await fetch("docsIf31CmDsOfdmChanChannelId", ChannelId),
            docsIf31CmDsOfdmChanChanIndicator             = DocsIf31CmDsOfdmChanIndicator.from_int(
                await fetch("docsIf31CmDsOfdmChanChanIndicator", int),
            ),
            docsIf31CmDsOfdmChanSubcarrierZeroFreq        = await fetch("docsIf31CmDsOfdmChanSubcarrierZeroFreq", FrequencyHz),
            docsIf31CmDsOfdmChanFirstActiveSubcarrierNum  = await fetch("docsIf31CmDsOfdmChanFirstActiveSubcarrierNum", int),
            docsIf31CmDsOfdmChanLastActiveSubcarrierNum   = await fetch("docsIf31CmDsOfdmChanLastActiveSubcarrierNum", int),
            docsIf31CmDsOfdmChanNumActiveSubcarriers      = await fetch("docsIf31CmDsOfdmChanNumActiveSubcarriers", int),
            docsIf31CmDsOfdmChanSubcarrierSpacing         = await fetch("docsIf31CmDsOfdmChanSubcarrierSpacing", int) * KHZ,
            docsIf31CmDsOfdmChanCyclicPrefix              = await fetch("docsIf31CmDsOfdmChanCyclicPrefix", int),
            docsIf31CmDsOfdmChanRollOffPeriod             = await fetch("docsIf31CmDsOfdmChanRollOffPeriod", int),
            docsIf31CmDsOfdmChanPlcFreq                   = await fetch("docsIf31CmDsOfdmChanPlcFreq", FrequencyHz),
            docsIf31CmDsOfdmChanNumPilots                 = await fetch("docsIf31CmDsOfdmChanNumPilots", int),
            docsIf31CmDsOfdmChanTimeInterleaverDepth      = await fetch("docsIf31CmDsOfdmChanTimeInterleaverDepth", int),
            docsIf31CmDsOfdmChanPlcTotalCodewords         = await fetch("docsIf31CmDsOfdmChanPlcTotalCodewords", int),
            docsIf31CmDsOfdmChanPlcUnreliableCodewords    = await fetch("docsIf31CmDsOfdmChanPlcUnreliableCodewords", int),
            docsIf31CmDsOfdmChanNcpTotalFields            = await fetch("docsIf31CmDsOfdmChanNcpTotalFields", int),
            docsIf31CmDsOfdmChanNcpFieldCrcFailures       = await fetch("docsIf31CmDsOfdmChanNcpFieldCrcFailures", int),
        )

        return cls(
            index      = index,
            channel_id = entry.docsIf31CmDsOfdmChanChannelId or 0,
            entry      = entry
        )

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf31CmDsOfdmChanChannelEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsIf31CmDsOfdmChanChannelEntry] = []

        if not indices:
            logger.warning("No OFDM channel indices provided.")
            return results

        for i in indices:
            entry = await cls.from_snmp(i, snmp)
            if entry.entry.docsIf31CmDsOfdmChanChannelId != INVALID_CHANNEL_ID:
                results.append(entry)
            else:
                logger.warning(f"Failed to retrieve OFDM channel {i}: invalid channel ID")

        return results

    # NEW: entries-only helper to accommodate your existing method signature.
    @classmethod
    async def get_entries(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf31CmDsOfdmChanEntry]:
        """
        Convenience wrapper that returns only the `DocsIf31CmDsOfdmChanEntry`
        objects (no channel wrapper), preserving a return type of
        `List[DocsIf31CmDsOfdmChanEntry]`.

        This is intended to fit code like:
            await self.getDocsIf31CmDsOfdmChanEntry() -> List[DocsIf31CmDsOfdmChanEntry]
        """
        wrappers = await cls.get(snmp, indices)
        return [w.entry for w in wrappers]
