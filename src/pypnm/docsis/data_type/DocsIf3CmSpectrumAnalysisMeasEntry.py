# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import ClassVar

from pydantic import BaseModel, Field

from pypnm.lib.types import FrequencyHz, PowerdBmV
from pypnm.snmp.casts import as_int
from pypnm.snmp.snmp_v2c import Snmp_v2c

SPECTRUM_TOTAL_SEGMENT_POWER_SCALE: float = 0.1


class DocsIf3CmSpectrumAnalysisMeasEntryFields(BaseModel):
    docsIf3CmSpectrumAnalysisMeasFrequency: FrequencyHz = Field(..., description="Measured center frequency for the spectrum analysis segment in Hz.")
    docsIf3CmSpectrumAnalysisMeasAmplitudeData: bytes = Field(..., description="Raw AmplitudeData payload encoded per DOCSIS SNMP textual convention.")
    docsIf3CmSpectrumAnalysisMeasTotalSegmentPower: PowerdBmV = Field(..., description="Total segment power in dBmV (tenths-of-dBmV scaled to decimal).")


class DocsIf3CmSpectrumAnalysisMeasEntry(BaseModel):
    index: int = Field(..., description="SNMP row index for the spectrum analysis measurement entry.")
    entry: DocsIf3CmSpectrumAnalysisMeasEntryFields = Field(..., description="Spectrum analysis measurement values for the given index.")

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIf3CmSpectrumAnalysisMeasEntry:
        """
        Fetch A Single Spectrum Analysis Measurement Row Via SNMP.

        Parameters
        ----------
        index : int
            Row index to query.
        snmp : Snmp_v2c
            Configured SNMP v2c client.

        Returns
        -------
        DocsIf3CmSpectrumAnalysisMeasEntry
            Typed measurement entry with total segment power scaled by 0.1.

        Raises
        ------
        ValueError
            If any required field is missing from the SNMP response.
        """
        log = logging.getLogger(cls.__name__)

        async def fetch_value(sym: str, caster: Callable[[str], int] | None = None) -> int | str | None:
            try:
                res = await snmp.get(f"{sym}.{index}")
                raw_values = Snmp_v2c.get_result_value(res)
                raw = raw_values[0] if raw_values else None
                if raw is None:
                    return None
                return caster(raw) if caster else raw
            except Exception as exc:
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s error=%r", index, sym, exc)
                return None

        async def fetch_bytes(sym: str) -> bytes | None:
            try:
                res = await snmp.get(f"{sym}.{index}")
                raw_bytes = Snmp_v2c.snmp_get_result_bytes(res)
                return raw_bytes[0] if raw_bytes else None
            except Exception as exc:
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s error=%r", index, sym, exc)
                return None

        freq = await fetch_value("docsIf3CmSpectrumAnalysisMeasFrequency", as_int)
        amp = await fetch_bytes("docsIf3CmSpectrumAnalysisMeasAmplitudeData")
        power_raw = await fetch_value("docsIf3CmSpectrumAnalysisMeasTotalSegmentPower")

        missing = {
            k: v for k, v in dict(
                frequency=freq,
                amplitude_data=amp,
                total_segment_power=power_raw,
            ).items() if v is None
        }
        if missing:
            raise ValueError(
                f"SpectrumAnalysisMeas idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        power_value = float(power_raw) * SPECTRUM_TOTAL_SEGMENT_POWER_SCALE
        entry = DocsIf3CmSpectrumAnalysisMeasEntryFields(
            docsIf3CmSpectrumAnalysisMeasFrequency=FrequencyHz(int(freq)),
            docsIf3CmSpectrumAnalysisMeasAmplitudeData=bytes(amp),
            docsIf3CmSpectrumAnalysisMeasTotalSegmentPower=PowerdBmV(power_value),
        )
        return cls(index=index, entry=entry)

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf3CmSpectrumAnalysisMeasEntry]:
        """
        Batch Fetch Spectrum Analysis Measurement Rows.

        Parameters
        ----------
        snmp : Snmp_v2c
            Configured SNMP v2c client used for all row queries.
        indices : list[int]
            List of row indices to query.

        Returns
        -------
        list[DocsIf3CmSpectrumAnalysisMeasEntry]
            Collected entries in the same order as `indices`. Empty if none.
        """
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]
