
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import DocsIf3CmStatusUsRangingStatus
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIfUpstreamEntry(BaseModel):
    docsIfUpChannelId: int | None = None
    docsIfUpChannelFrequency: int | None = None
    docsIfUpChannelWidth: int | None = None
    docsIfUpChannelModulationProfile: int | None = None
    docsIfUpChannelSlotSize: int | None = None
    docsIfUpChannelTxTimingOffset: int | None = None
    docsIfUpChannelRangingBackoffStart: int | None = None
    docsIfUpChannelRangingBackoffEnd: int | None = None
    docsIfUpChannelTxBackoffStart: int | None = None
    docsIfUpChannelTxBackoffEnd: int | None = None
    docsIfUpChannelType: int | None = None
    docsIfUpChannelCloneFrom: int | None = None
    docsIfUpChannelUpdate: bool | None = None
    docsIfUpChannelStatus: int | None = None
    docsIfUpChannelPreEqEnable: bool | None = None

    # DOCS-IF3-MIB extensions
    docsIf3CmStatusUsTxPower: float | None = None
    docsIf3CmStatusUsT3Timeouts: int | None = None
    docsIf3CmStatusUsT4Timeouts: int | None = None
    docsIf3CmStatusUsRangingAborteds: int | None = None
    docsIf3CmStatusUsModulationType: int | None = None
    docsIf3CmStatusUsEqData: str | None = None
    docsIf3CmStatusUsT3Exceededs: int | None = None
    docsIf3CmStatusUsIsMuted: bool | None = None
    docsIf3CmStatusUsRangingStatus: DocsIf3CmStatusUsRangingStatus | None = None

class DocsIfUpstreamChannelEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsIfUpstreamEntry

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIfUpstreamChannelEntry | None:
        logger = logging.getLogger(cls.__name__)

        def tenthdBmV_to_float(value: str) -> float | None:
            try:
                return float(value) / 10.0
            except Exception:
                return None

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
                if cast:
                    return safe_cast(val, cast)
                val = val.strip()
                if val.isdigit():
                    return int(val)
                if val.lower() in ("true", "false"):
                    return val.lower() == "true"
                try:
                    return float(val)
                except ValueError:
                    return val
            except Exception as e:
                logger.warning(f"Failed to fetch {field}: {e}")
                return None

        entry = DocsIfUpstreamEntry(
            docsIfUpChannelId                   =   await fetch("docsIfUpChannelId", int),
            docsIfUpChannelFrequency            =   await fetch("docsIfUpChannelFrequency", int),
            docsIfUpChannelWidth                =   await fetch("docsIfUpChannelWidth", int),
            docsIfUpChannelModulationProfile    =   await fetch("docsIfUpChannelModulationProfile", int),
            docsIfUpChannelSlotSize             =   await fetch("docsIfUpChannelSlotSize", int),
            docsIfUpChannelTxTimingOffset       =   await fetch("docsIfUpChannelTxTimingOffset", int),
            docsIfUpChannelRangingBackoffStart =   await fetch("docsIfUpChannelRangingBackoffStart", int),
            docsIfUpChannelRangingBackoffEnd   =   await fetch("docsIfUpChannelRangingBackoffEnd", int),
            docsIfUpChannelTxBackoffStart      =   await fetch("docsIfUpChannelTxBackoffStart", int),
            docsIfUpChannelTxBackoffEnd        =   await fetch("docsIfUpChannelTxBackoffEnd", int),
            docsIfUpChannelType                =   await fetch("docsIfUpChannelType", int),
            docsIfUpChannelCloneFrom           =   await fetch("docsIfUpChannelCloneFrom", int),
            docsIfUpChannelUpdate              =   await fetch("docsIfUpChannelUpdate", Snmp_v2c.truth_value),
            docsIfUpChannelStatus              =   await fetch("docsIfUpChannelStatus", int),
            docsIfUpChannelPreEqEnable         =   await fetch("docsIfUpChannelPreEqEnable", Snmp_v2c.truth_value),

            docsIf3CmStatusUsTxPower           =   await fetch("docsIf3CmStatusUsTxPower", tenthdBmV_to_float),
            docsIf3CmStatusUsT3Timeouts        =   await fetch("docsIf3CmStatusUsT3Timeouts", int),
            docsIf3CmStatusUsT4Timeouts        =   await fetch("docsIf3CmStatusUsT4Timeouts", int),
            docsIf3CmStatusUsRangingAborteds   =   await fetch("docsIf3CmStatusUsRangingAborteds", int),
            docsIf3CmStatusUsModulationType    =   await fetch("docsIf3CmStatusUsModulationType", int),
            docsIf3CmStatusUsEqData            =   await fetch("docsIf3CmStatusUsEqData", str),
            docsIf3CmStatusUsT3Exceededs       =   await fetch("docsIf3CmStatusUsT3Exceededs", int),
            docsIf3CmStatusUsIsMuted           =   await fetch("docsIf3CmStatusUsIsMuted", Snmp_v2c.truth_value),
            docsIf3CmStatusUsRangingStatus     =   DocsIf3CmStatusUsRangingStatus.from_int(
                await fetch("docsIf3CmStatusUsRangingStatus", int),
            )
        )

        return cls(
            index=index,
            channel_id=entry.docsIfUpChannelId or 0,
            entry=entry
        )

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIfUpstreamChannelEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsIfUpstreamChannelEntry] = []

        if not indices:
            logger.warning("No upstream ATDMA indices found.")
            return results

        for index in indices:
            result = await cls.from_snmp(index, snmp)
            if result is not None:
                results.append(result)

        return results
