# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, ClassVar, cast

from pydantic import BaseModel

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.lib.types import FrequencyHz
from pypnm.snmp.casts import as_bool, as_float2, as_int, as_str  # freq stays int
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsPnmCmDsOfdmRxMerFields(BaseModel):
    docsPnmCmDsOfdmRxMerFileEnable: bool
    docsPnmCmDsOfdmRxMerFileName: str
    docsPnmCmDsOfdmRxMerMeasStatus: str
    docsPnmCmDsOfdmRxMerPercentile: float
    docsPnmCmDsOfdmRxMerMean: float
    docsPnmCmDsOfdmRxMerStdDev: float
    docsPnmCmDsOfdmRxMerThrVal: float
    docsPnmCmDsOfdmRxMerThrHighestFreq: FrequencyHz


class DocsPnmCmDsOfdmRxMerEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsPnmCmDsOfdmRxMerFields

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsPnmCmDsOfdmRxMerEntry:
        log = logging.getLogger(cls.__name__)

        async def fetch(
            sym: str, caster: Callable[[Any], Any] | None = None
        ) -> str | int | float | bool | None:
            try:
                res = await snmp.get(f"{sym}.{index}")
                raw = Snmp_v2c.get_result_value(res)
                val = caster(raw) if (caster and raw is not None) else raw
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s raw=%r cast=%r", index, sym, raw, val)
                return val
            except Exception as e:
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s error=%r", index, sym, e)
                return None

        file_enable = cast(bool, await fetch("docsPnmCmDsOfdmRxMerFileEnable", as_bool))
        file_name = cast(str, await fetch("docsPnmCmDsOfdmRxMerFileName", as_str))
        meas_statusi = cast(int, await fetch("docsPnmCmDsOfdmRxMerMeasStatus", as_int))
        perc = cast(float, await fetch("docsPnmCmDsOfdmRxMerPercentile", as_float2))
        mean = cast(float, await fetch("docsPnmCmDsOfdmRxMerMean", as_float2))
        stddev = cast(float, await fetch("docsPnmCmDsOfdmRxMerStdDev", as_float2))
        thr_val = cast(float, await fetch("docsPnmCmDsOfdmRxMerThrVal", as_float2))
        freq_hz_raw = cast(
            int, await fetch("docsPnmCmDsOfdmRxMerThrHighestFreq", as_int)
        )

        # Enforce non-optional: fail fast if any missing (check raw int for status)
        missing = {
            k: v
            for k, v in dict(
                file_enable=file_enable,
                file_name=file_name,
                meas_status=meas_statusi,
                perc=perc,
                mean=mean,
                stddev=stddev,
                thr_val=thr_val,
                freq_hz_raw=freq_hz_raw,
            ).items()
            if v is None
        }
        if missing:
            raise ValueError(
                f"RxMER idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        # Map status int → enum → lowercase string (fallback to "other")
        try:
            meas_statuss = str(MeasStatusType(meas_statusi))
        except Exception:
            meas_statuss = str(MeasStatusType.OTHER)

        entry = DocsPnmCmDsOfdmRxMerFields(
            docsPnmCmDsOfdmRxMerFileEnable=bool(file_enable),
            docsPnmCmDsOfdmRxMerFileName=str(file_name),
            docsPnmCmDsOfdmRxMerMeasStatus=meas_statuss,
            docsPnmCmDsOfdmRxMerPercentile=float(perc),
            docsPnmCmDsOfdmRxMerMean=float(mean),
            docsPnmCmDsOfdmRxMerStdDev=float(stddev),
            docsPnmCmDsOfdmRxMerThrVal=float(thr_val),
            docsPnmCmDsOfdmRxMerThrHighestFreq=cast(FrequencyHz, freq_hz_raw),
        )
        return cls(index=index, channel_id=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmDsOfdmRxMerEntry]:
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]
