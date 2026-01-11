from __future__ import annotations

import logging

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsPnmCmDsOfdmMerMarFields(BaseModel):
    docsPnmCmDsOfdmMerMarProfileId: int | None = None
    docsPnmCmDsOfdmMerMarThrshldOffset: int | None = None
    docsPnmCmDsOfdmMerMarMeasEnable: bool | None = None
    docsPnmCmDsOfdmMerMarNumSymPerSubCarToAvg: int | None = None
    docsPnmCmDsOfdmMerMarReqAvgMer: int | None = None
    docsPnmCmDsOfdmMerMarNumSubCarBelowThrshld: int | None = None
    docsPnmCmDsOfdmMerMarMeasuredAvgMer: int | None = None
    docsPnmCmDsOfdmMerMarAvgMerMargin: int | None = None
    docsPnmCmDsOfdmMerMarMeasStatus: int | None = None


class DocsPnmCmDsOfdmMerMarEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsPnmCmDsOfdmMerMarFields

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsPnmCmDsOfdmMerMarEntry:
        logger = logging.getLogger(cls.__name__)

        async def fetch(
            oid: str, cast: Callable | None = None
        ) -> str | int | float | bool | None:
            try:
                result = await snmp.get(f"{oid}.{index}")
                value = Snmp_v2c.get_result_value(result)

                if value is None:
                    return None

                if cast:
                    return cast(value)

                return value

            except Exception as e:
                logger.warning(f"Fetch error for {oid}.{index}: {e}")
                return None

        entry = DocsPnmCmDsOfdmMerMarFields(
            docsPnmCmDsOfdmMerMarProfileId=await fetch(
                "docsPnmCmDsOfdmMerMarProfileId", int
            ),
            docsPnmCmDsOfdmMerMarThrshldOffset=await fetch(
                "docsPnmCmDsOfdmMerMarThrshldOffset", int
            ),
            docsPnmCmDsOfdmMerMarMeasEnable=await fetch(
                "docsPnmCmDsOfdmMerMarMeasEnable", Snmp_v2c.truth_value
            ),
            docsPnmCmDsOfdmMerMarNumSymPerSubCarToAvg=await fetch(
                "docsPnmCmDsOfdmMerMarNumSymPerSubCarToAvg", int
            ),
            docsPnmCmDsOfdmMerMarReqAvgMer=await fetch(
                "docsPnmCmDsOfdmMerMarReqAvgMer", int
            ),
            docsPnmCmDsOfdmMerMarNumSubCarBelowThrshld=await fetch(
                "docsPnmCmDsOfdmMerMarNumSubCarBelowThrshld", int
            ),
            docsPnmCmDsOfdmMerMarMeasuredAvgMer=await fetch(
                "docsPnmCmDsOfdmMerMarMeasuredAvgMer", int
            ),
            docsPnmCmDsOfdmMerMarAvgMerMargin=await fetch(
                "docsPnmCmDsOfdmMerMarAvgMerMargin", int
            ),
            docsPnmCmDsOfdmMerMarMeasStatus=await fetch(
                "docsPnmCmDsOfdmMerMarMeasStatus", int
            ),
        )

        return cls(index=index, channel_id=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmDsOfdmMerMarEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsPnmCmDsOfdmMerMarEntry] = []

        import asyncio

        tasks = [cls.from_snmp(idx, snmp) for idx in indices]
        gathered_results = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, result in zip(indices, gathered_results, strict=False):
            if isinstance(result, Exception):
                logger.warning(
                    f"Failed to fetch OFDM MER Margin entry for index {idx}: {result}"
                )
            else:
                results.append(result)

        return results
