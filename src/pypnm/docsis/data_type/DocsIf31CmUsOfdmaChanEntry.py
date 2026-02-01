
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import DocsIf31CmStatusOfdmaUsRangingStatus
from pypnm.lib.types import ChannelId, FrequencyHz
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIf31CmUsOfdmaChan(BaseModel):
    docsIf31CmUsOfdmaChanChannelId: ChannelId | None = None
    docsIf31CmUsOfdmaChanConfigChangeCt: int | None = None
    docsIf31CmUsOfdmaChanSubcarrierZeroFreq: FrequencyHz | None = None
    docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum: int | None = None
    docsIf31CmUsOfdmaChanLastActiveSubcarrierNum: int | None = None
    docsIf31CmUsOfdmaChanNumActiveSubcarriers: int | None = None
    docsIf31CmUsOfdmaChanSubcarrierSpacing: FrequencyHz | None = None
    docsIf31CmUsOfdmaChanCyclicPrefix: int | None = None
    docsIf31CmUsOfdmaChanRollOffPeriod: int | None = None
    docsIf31CmUsOfdmaChanNumSymbolsPerFrame: int | None = None
    docsIf31CmUsOfdmaChanTxPower: float | None = None
    docsIf31CmUsOfdmaChanPreEqEnabled: bool | None = None
    docsIf31CmStatusOfdmaUsT3Timeouts: int | None = None
    docsIf31CmStatusOfdmaUsT4Timeouts: int | None = None
    docsIf31CmStatusOfdmaUsRangingAborteds: int | None = None
    docsIf31CmStatusOfdmaUsT3Exceededs: int | None = None
    docsIf31CmStatusOfdmaUsIsMuted: bool | None = None
    docsIf31CmStatusOfdmaUsRangingStatus: DocsIf31CmStatusOfdmaUsRangingStatus | None = None

class DocsIf31CmUsOfdmaChanEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsIf31CmUsOfdmaChan

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIf31CmUsOfdmaChanEntry | None:
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

        entry = DocsIf31CmUsOfdmaChan(
            docsIf31CmUsOfdmaChanChannelId                  =   await fetch("docsIf31CmUsOfdmaChanChannelId", int),
            docsIf31CmUsOfdmaChanConfigChangeCt             =   await fetch("docsIf31CmUsOfdmaChanConfigChangeCt", int),
            docsIf31CmUsOfdmaChanSubcarrierZeroFreq         =   await fetch("docsIf31CmUsOfdmaChanSubcarrierZeroFreq", int),
            docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum   =   await fetch("docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum", int),
            docsIf31CmUsOfdmaChanLastActiveSubcarrierNum    =   await fetch("docsIf31CmUsOfdmaChanLastActiveSubcarrierNum", int),
            docsIf31CmUsOfdmaChanNumActiveSubcarriers       =   await fetch("docsIf31CmUsOfdmaChanNumActiveSubcarriers", int),
            docsIf31CmUsOfdmaChanSubcarrierSpacing          =   await fetch("docsIf31CmUsOfdmaChanSubcarrierSpacing", int),
            docsIf31CmUsOfdmaChanCyclicPrefix               =   await fetch("docsIf31CmUsOfdmaChanCyclicPrefix", int),
            docsIf31CmUsOfdmaChanRollOffPeriod              =   await fetch("docsIf31CmUsOfdmaChanRollOffPeriod", int),
            docsIf31CmUsOfdmaChanNumSymbolsPerFrame         =   await fetch("docsIf31CmUsOfdmaChanNumSymbolsPerFrame", int),
            docsIf31CmUsOfdmaChanTxPower                    =   await fetch("docsIf31CmUsOfdmaChanTxPower", tenthdBmV_to_float),
            docsIf31CmUsOfdmaChanPreEqEnabled               =   await fetch("docsIf31CmUsOfdmaChanPreEqEnabled", Snmp_v2c.truth_value),
            docsIf31CmStatusOfdmaUsT3Timeouts               =   await fetch("docsIf31CmStatusOfdmaUsT3Timeouts", int),
            docsIf31CmStatusOfdmaUsT4Timeouts               =   await fetch("docsIf31CmStatusOfdmaUsT4Timeouts", int),
            docsIf31CmStatusOfdmaUsRangingAborteds          =   await fetch("docsIf31CmStatusOfdmaUsRangingAborteds", int),
            docsIf31CmStatusOfdmaUsT3Exceededs              =   await fetch("docsIf31CmStatusOfdmaUsT3Exceededs", int),
            docsIf31CmStatusOfdmaUsIsMuted                  =   await fetch("docsIf31CmStatusOfdmaUsIsMuted", Snmp_v2c.truth_value),
            docsIf31CmStatusOfdmaUsRangingStatus            =   DocsIf31CmStatusOfdmaUsRangingStatus.from_int(
                await fetch("docsIf31CmStatusOfdmaUsRangingStatus", int),
            )
        )

        try:
            return cls(
                index           =   index,
                channel_id      =   entry.docsIf31CmUsOfdmaChanChannelId or 0,
                entry           =   entry
            )
        except Exception as e:
            logger.warning(f"Failed to retrieve OFDMA channel {index}: {e}")
            return None

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf31CmUsOfdmaChanEntry]:
        results: list[DocsIf31CmUsOfdmaChanEntry] = []

        for index in indices:
            result = await cls.from_snmp(index, snmp)
            if result is not None:
                results.append(result)

        return results
