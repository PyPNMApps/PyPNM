from __future__ import annotations

import logging

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.pnm.data_type.DsOfdmModulationType import DsOfdmModulationType
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsPnmCmDsConstDispFields(BaseModel):
    docsPnmCmDsConstDispTrigEnable: bool
    docsPnmCmDsConstDispModOrderOffset: int
    docsPnmCmDsConstDispNumSampleSymb: int
    docsPnmCmDsConstDispSelModOrder: str  # e.g., "qam256"
    docsPnmCmDsConstDispMeasStatus: str  # e.g., "sample_ready"
    docsPnmCmDsConstDispFileName: str


class DocsPnmCmDsConstDispMeasEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsPnmCmDsConstDispFields

    @classmethod
    async def from_snmp(
        cls, index: int, snmp: Snmp_v2c
    ) -> DocsPnmCmDsConstDispMeasEntry:
        logger = logging.getLogger(cls.__name__)

        async def fetch(
            oid: str, cast: Callable | None = None
        ) -> str | int | bool | None:
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

        # Raw values
        trig_enable = await fetch(
            "docsPnmCmDsConstDispTrigEnable", Snmp_v2c.truth_value
        )
        mod_order_offset = await fetch("docsPnmCmDsConstDispModOrderOffset", int)
        num_sample_symb = await fetch("docsPnmCmDsConstDispNumSampleSymb", int)
        sel_mod_order_i = await fetch("docsPnmCmDsConstDispSelModOrder", int)
        meas_status_i = await fetch("docsPnmCmDsConstDispMeasStatus", int)
        file_name = await fetch("docsPnmCmDsConstDispFileName", str)

        # Map ints → enum names (strings)
        # Modulation: use helper that tolerates unknowns
        sel_mod_order_s = (
            DsOfdmModulationType.get_name(int(sel_mod_order_i))
            if sel_mod_order_i is not None
            else DsOfdmModulationType.UNKNOWN.name
        )
        sel_mod_order_s = (
            sel_mod_order_s.lower()
        )  # keep consistent with your style ("qam256", "qpsk", etc.)

        # Measurement status: map to Enum; fall back to "unknown" if needed
        if meas_status_i is not None:
            try:
                meas_status_s = str(
                    MeasStatusType(meas_status_i)
                )  # __str__ lowers the name
            except Exception:
                meas_status_s = "unknown"
        else:
            meas_status_s = "unknown"

        entry = DocsPnmCmDsConstDispFields(
            docsPnmCmDsConstDispTrigEnable=bool(trig_enable)
            if trig_enable is not None
            else False,
            docsPnmCmDsConstDispModOrderOffset=int(mod_order_offset or 0),
            docsPnmCmDsConstDispNumSampleSymb=int(num_sample_symb or 0),
            docsPnmCmDsConstDispSelModOrder=sel_mod_order_s,
            docsPnmCmDsConstDispMeasStatus=meas_status_s,
            docsPnmCmDsConstDispFileName=str(file_name or ""),
        )

        return cls(index=index, channel_id=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmDsConstDispMeasEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsPnmCmDsConstDispMeasEntry] = []
        errors: list[tuple[int, Exception]] = []

        for idx in indices:
            entry = await cls.from_snmp(idx, snmp)
            if entry is not None:
                results.append(entry)

        for idx, error in errors:
            logger.warning(
                f"Failed to fetch Constellation Display entry for index {idx}: {error}"
            )

        return results
