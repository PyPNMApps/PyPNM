# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, ClassVar, cast

from pydantic import BaseModel, Field

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.snmp.casts import as_bool, as_int, as_str
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsPnmCmDsHistEntryFields(BaseModel):
    docsPnmCmDsHistEnable: bool = Field(
        ..., description="Histogram file capture enable state"
    )
    docsPnmCmDsHistTimeOut: int = Field(
        ..., description="Histogram measurement timeout in seconds"
    )
    docsPnmCmDsHistMeasStatus: str = Field(
        ..., description="Measurement status (enum string)"
    )
    docsPnmCmDsHistFileName: str = Field(
        ..., description="Result filename on the TFTP server"
    )


class DocsPnmCmDsHistEntry(BaseModel):
    index: int = Field(..., description="SNMP row index (device-specific)")
    entry: DocsPnmCmDsHistEntryFields = Field(
        ..., description="Flattened histogram control/status fields"
    )

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsPnmCmDsHistEntry:
        """
        Fetch a single DOCSIS Downstream Histogram control/status row via SNMP.

        Parameters
        ----------
        index : int
            Row index to query (e.g., device row id).
        snmp : Snmp_v2c
            Configured SNMP v2c client. Must support `get(sym.index)` and `get_result_value`.

        Returns
        -------
        DocsPnmCmDsHistEntry
            Typed entry with enum status converted to a lowercase string.

        Raises
        ------
        ValueError
            If any required field is missing from the SNMP agent response.
        """
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
                return cast(str | int | float | bool | None, val)
            except Exception as e:
                if cls.DEBUG and log.isEnabledFor(logging.DEBUG):
                    log.debug("idx=%s %s error=%r", index, sym, e)
                return None

        enable = cast(bool, await fetch("docsPnmCmDsHistEnable", as_bool))
        timeout = cast(int, await fetch("docsPnmCmDsHistTimeOut", as_int))
        meas_status_i = cast(int, await fetch("docsPnmCmDsHistMeasStatus", as_int))
        file_name = cast(str, await fetch("docsPnmCmDsHistFileName", as_str))

        missing = {
            k: v
            for k, v in dict(
                enable=enable,
                timeout=timeout,
                meas_status_i=meas_status_i,
                file_name=file_name,
            ).items()
            if v is None
        }
        if missing:
            raise ValueError(
                f"Histogram idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        try:
            meas_status_s = str(MeasStatusType(meas_status_i))
        except Exception:
            meas_status_s = str(MeasStatusType.OTHER)

        entry = DocsPnmCmDsHistEntryFields(
            docsPnmCmDsHistEnable=bool(enable),
            docsPnmCmDsHistTimeOut=int(timeout),
            docsPnmCmDsHistMeasStatus=meas_status_s,
            docsPnmCmDsHistFileName=str(file_name),
        )
        return cls(index=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmDsHistEntry]:
        """
        Batch fetch multiple histogram rows.

        Parameters
        ----------
        snmp : Snmp_v2c
            Configured SNMP v2c client.
        indices : List[int]
            List of row indices to query.

        Returns
        -------
        List[DocsPnmCmDsHistEntry]
            Collected entries in the same order as `indices`. Empty if none.
        """
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]
