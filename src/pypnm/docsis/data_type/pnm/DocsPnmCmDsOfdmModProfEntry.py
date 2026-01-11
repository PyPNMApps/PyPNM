# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, ClassVar, cast

from pydantic import BaseModel

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.snmp.casts import as_bool, as_int, as_str
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsPnmCmDsOfdmModProfFields(BaseModel):
    docsPnmCmDsOfdmModProfFileEnable: bool
    docsPnmCmDsOfdmModProfMeasStatus: str
    docsPnmCmDsOfdmModProfFileName: str


class DocsPnmCmDsOfdmModProfEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsPnmCmDsOfdmModProfFields

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsPnmCmDsOfdmModProfEntry:
        log = logging.getLogger(cls.__name__)

        async def fetch(
            sym: str,
            caster: Callable[[Any], Any] | None = None,
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

        file_enable = cast(
            bool, await fetch("docsPnmCmDsOfdmModProfFileEnable", as_bool)
        )
        meas_statusi = cast(
            int, await fetch("docsPnmCmDsOfdmModProfMeasStatus", as_int)
        )
        file_name = cast(str, await fetch("docsPnmCmDsOfdmModProfFileName", as_str))

        missing = {
            k: v
            for k, v in dict(
                file_enable=file_enable,
                meas_status=meas_statusi,
                file_name=file_name,
            ).items()
            if v is None
        }
        if missing:
            raise ValueError(
                f"ModProf idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        try:
            meas_statuss = str(MeasStatusType(meas_statusi))
        except Exception:
            meas_statuss = str(MeasStatusType.OTHER)

        entry = DocsPnmCmDsOfdmModProfFields(
            docsPnmCmDsOfdmModProfFileEnable=bool(file_enable),
            docsPnmCmDsOfdmModProfMeasStatus=meas_statuss,
            docsPnmCmDsOfdmModProfFileName=str(file_name),
        )

        return cls(index=index, channel_id=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmDsOfdmModProfEntry]:
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]
