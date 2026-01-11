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


class DocsPnmCmDsOfdmFecEntryFields(BaseModel):
    docsPnmCmDsOfdmFecSumType: str = Field(
        ...,
        description="Aggregation type/window (enum string, e.g., '24-hour interval')",
    )
    docsPnmCmDsOfdmFecFileEnable: bool = Field(
        ..., description="FEC summary file capture enable state"
    )
    docsPnmCmDsOfdmFecMeasStatus: str = Field(
        ..., description="Measurement status (enum string)"
    )
    docsPnmCmDsOfdmFecFileName: str = Field(
        ..., description="Result filename on the TFTP server"
    )


class DocsPnmCmDsOfdmFecEntry(BaseModel):
    index: int = Field(..., description="SNMP row index (device-specific)")
    entry: DocsPnmCmDsOfdmFecEntryFields = Field(
        ..., description="Flattened FEC summary control/status fields"
    )

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsPnmCmDsOfdmFecEntry:
        """
        Fetch a single DOCSIS Downstream OFDM FEC Summary control/status row via SNMP.

        Parameters
        ----------
        index : int
            Row index to query.
        snmp : Snmp_v2c
            Configured SNMP v2c client. Must support `get(sym.index)` and `get_result_value`.

        Returns
        -------
        DocsPnmCmDsOfdmFecEntry
            Typed entry with enum fields converted to readable strings.

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

        sum_type_i = cast(int, await fetch("docsPnmCmDsOfdmFecSumType", as_int))
        file_enable = cast(bool, await fetch("docsPnmCmDsOfdmFecFileEnable", as_bool))
        meas_status_i = cast(int, await fetch("docsPnmCmDsOfdmFecMeasStatus", as_int))
        file_name = cast(str, await fetch("docsPnmCmDsOfdmFecFileName", as_str))

        missing = {
            k: v
            for k, v in dict(
                sum_type_i=sum_type_i,
                file_enable=file_enable,
                meas_status_i=meas_status_i,
                file_name=file_name,
            ).items()
            if v is None
        }
        if missing:
            raise ValueError(
                f"OFDM FEC idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        # Convert MeasStatusType integer → readable string via enum
        try:
            meas_status_s = str(MeasStatusType(meas_status_i))
        except Exception:
            meas_status_s = str(MeasStatusType.OTHER)

        # Convert FEC Summary Type integer → readable string
        sum_type_s: str
        try:
            # Prefer project enum if available (keeps single source of truth)
            from pypnm.docsis.cm_snmp_operation import (
                FecSummaryType as _FecSummaryType,  # type: ignore
            )

            try:
                if hasattr(_FecSummaryType, "from_value"):
                    sum_type_s = str(
                        _FecSummaryType.from_value(int(sum_type_i))
                    )  # e.g., "24-hour interval"
                else:
                    sum_type_s = str(_FecSummaryType(int(sum_type_i)))
            except Exception:
                # Fallback friendly labels
                mapping = {1: "10-minute interval", 2: "24-hour interval"}
                sum_type_s = mapping.get(int(sum_type_i), f"unknown({sum_type_i})")
        except Exception:
            mapping = {1: "10-minute interval", 2: "24-hour interval"}
            sum_type_s = mapping.get(int(sum_type_i), f"unknown({sum_type_i})")

        entry = DocsPnmCmDsOfdmFecEntryFields(
            docsPnmCmDsOfdmFecSumType=sum_type_s,
            docsPnmCmDsOfdmFecFileEnable=bool(file_enable),
            docsPnmCmDsOfdmFecMeasStatus=meas_status_s,
            docsPnmCmDsOfdmFecFileName=str(file_name),
        )
        return cls(index=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmDsOfdmFecEntry]:
        """
        Batch fetch multiple OFDM FEC Summary rows.

        Parameters
        ----------
        snmp : Snmp_v2c
            Configured SNMP v2c client.
        indices : List[int]
            List of row indices to query.

        Returns
        -------
        List[DocsPnmCmDsOfdmFecEntry]
            Collected entries in the same order as `indices`. Empty if none.
        """
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]
