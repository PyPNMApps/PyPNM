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


class DocsIf3CmSpectrumAnalysisEntryFields(BaseModel):
    docsIf3CmSpectrumAnalysisCtrlCmdEnable: bool = Field(
        ...,
        description="Spectrum analyzer enable state; true starts measurements based on configured attributes.",
    )
    docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout: int = Field(
        ...,
        description="Inactivity timeout in seconds after the last measurement before the feature is disabled; 0 keeps it enabled until explicitly disabled.",
    )
    docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency: int = Field(
        ..., description="Center frequency of the first segment in Hz."
    )
    docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency: int = Field(
        ..., description="Center frequency of the last segment in Hz."
    )
    docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan: int = Field(
        ...,
        description="Frequency span in Hz of each segment between first and last center frequency.",
    )
    docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment: int = Field(
        ..., description="Number of FFT bins collected per segment."
    )
    docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth: int = Field(
        ...,
        description="Requested equivalent noise bandwidth in hundredths-of-bin units.",
    )
    docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction: int = Field(
        ..., description="Window function selector used for the spectrum analysis."
    )
    docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages: int = Field(
        ...,
        description="Configured number of averages (1..1000) for leaky-integrator bin averaging.",
    )
    docsIf3CmSpectrumAnalysisCtrlCmdFileEnable: bool = Field(
        ..., description="File-based spectrum result retrieval enable state."
    )
    docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus: str = Field(
        ...,
        description="Measurement status as a normalized enum string (e.g., 'sample_ready').",
    )
    docsIf3CmSpectrumAnalysisCtrlCmdFileName: str = Field(
        ..., description="Configured spectrum result filename (e.g., on TFTP server)."
    )


class DocsIf3CmSpectrumAnalysisEntry(BaseModel):
    index: int = Field(
        ...,
        description="SNMP row index for the spectrum analysis control/measurement entry.",
    )
    entry: DocsIf3CmSpectrumAnalysisEntryFields = Field(
        ..., description="Flattened spectrum analysis control and measurement fields."
    )

    DEBUG: ClassVar[bool] = False

    @classmethod
    async def from_snmp(
        cls, index: int, snmp: Snmp_v2c
    ) -> DocsIf3CmSpectrumAnalysisEntry:
        """
        Fetch A Single DOCSIS 3.1 Spectrum Analysis Control/Status Row Via SNMP.

        Parameters
        ----------
        index : int
            Row index to query (e.g., 0 for the primary CM instance).
        snmp : Snmp_v2c
            Configured SNMP v2c client. Must support `await get("sym.index")`
            and `Snmp_v2c.get_result_value(...)` to extract the value.

        Returns
        -------
        DocsIf3CmSpectrumAnalysisEntry
            Typed entry with measurement status converted to a normalized
            enum string via MeasStatusType.

        Raises
        ------
        ValueError
            If any required field is missing from the SNMP agent response.
        """
        log = logging.getLogger(cls.__name__)

        async def fetch(
            sym: str, caster: Callable[[Any], Any] | None = None
        ) -> str | int | float | bool | None:
            """
            Helper To Fetch And Optionally Cast A Single SNMP Symbol For This Index.

            Returns the cast value or None if an error occurs or the value
            cannot be retrieved.
            """
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

        enable = cast(
            bool, await fetch("docsIf3CmSpectrumAnalysisCtrlCmdEnable", as_bool)
        )
        timeout = cast(
            int,
            await fetch("docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout", as_int),
        )
        first_cf = cast(
            int,
            await fetch(
                "docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency", as_int
            ),
        )
        last_cf = cast(
            int,
            await fetch(
                "docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency", as_int
            ),
        )
        span_hz = cast(
            int,
            await fetch("docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan", as_int),
        )
        num_bins = cast(
            int,
            await fetch("docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment", as_int),
        )
        enbw = cast(
            int,
            await fetch(
                "docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth", as_int
            ),
        )
        window_fn = cast(
            int, await fetch("docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction", as_int)
        )
        num_avg = cast(
            int, await fetch("docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages", as_int)
        )
        file_enable = cast(
            bool, await fetch("docsIf3CmSpectrumAnalysisCtrlCmdFileEnable", as_bool)
        )
        meas_status_i = cast(
            int, await fetch("docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus", as_int)
        )
        file_name = cast(
            str, await fetch("docsIf3CmSpectrumAnalysisCtrlCmdFileName", as_str)
        )

        missing = {
            k: v
            for k, v in dict(
                enable=enable,
                timeout=timeout,
                first_cf=first_cf,
                last_cf=last_cf,
                span_hz=span_hz,
                num_bins=num_bins,
                enbw=enbw,
                window_fn=window_fn,
                num_avg=num_avg,
                file_enable=file_enable,
                meas_status_i=meas_status_i,
                file_name=file_name,
            ).items()
            if v is None
        }
        if missing:
            raise ValueError(
                f"SpectrumAnalysis idx={index}: missing required fields: {', '.join(missing.keys())}"
            )

        try:
            meas_status_s = str(MeasStatusType(meas_status_i))
        except Exception:
            meas_status_s = str(MeasStatusType.OTHER)

        entry = DocsIf3CmSpectrumAnalysisEntryFields(
            docsIf3CmSpectrumAnalysisCtrlCmdEnable=bool(enable),
            docsIf3CmSpectrumAnalysisCtrlCmdInactivityTimeout=int(timeout),
            docsIf3CmSpectrumAnalysisCtrlCmdFirstSegmentCenterFrequency=int(first_cf),
            docsIf3CmSpectrumAnalysisCtrlCmdLastSegmentCenterFrequency=int(last_cf),
            docsIf3CmSpectrumAnalysisCtrlCmdSegmentFrequencySpan=int(span_hz),
            docsIf3CmSpectrumAnalysisCtrlCmdNumBinsPerSegment=int(num_bins),
            docsIf3CmSpectrumAnalysisCtrlCmdEquivalentNoiseBandwidth=int(enbw),
            docsIf3CmSpectrumAnalysisCtrlCmdWindowFunction=int(window_fn),
            docsIf3CmSpectrumAnalysisCtrlCmdNumberOfAverages=int(num_avg),
            docsIf3CmSpectrumAnalysisCtrlCmdFileEnable=bool(file_enable),
            docsIf3CmSpectrumAnalysisCtrlCmdMeasStatus=meas_status_s,
            docsIf3CmSpectrumAnalysisCtrlCmdFileName=str(file_name),
        )
        return cls(index=index, entry=entry)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsIf3CmSpectrumAnalysisEntry]:
        """
        Batch Fetch Multiple Spectrum Analysis Rows.

        Parameters
        ----------
        snmp : Snmp_v2c
            Configured SNMP v2c client used for all row queries.
        indices : List[int]
            List of row indices to query (e.g., [0] for a single-CM instance).

        Returns
        -------
        List[DocsIf3CmSpectrumAnalysisEntry]
            Collected entries in the same order as `indices`. Empty if none.
        """
        if not indices:
            return []
        return [await cls.from_snmp(idx, snmp) for idx in indices]
