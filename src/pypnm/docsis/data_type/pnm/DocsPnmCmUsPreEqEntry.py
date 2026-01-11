from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
import logging
from collections.abc import Callable
from enum import Enum
from typing import TypeVar

from pydantic import BaseModel

from pypnm.lib.types import ChannelId
from pypnm.snmp.casts import measurement_status
from pypnm.snmp.snmp_v2c import Snmp_v2c

T = TypeVar("T")


class PreEqCoAdjStatus(Enum):
    """
    Enumeration of docsPnmCmUsPreEqPreEqCoAdjStatus.

    docsPnmCmUsPreEqPreEqCoAdjStatus OBJECT-TYPE
        SYNTAX      INTEGER {
                        other(1),
                        success(2),
                        clipped(3),
                        rejected(4)
                    }

    This represents whether the last set of Pre-Equalization coefficient
    adjustments were fully applied, clipped, rejected, or in some other state.

    Reference:
        CM-SP-CM-OSSI, CmUsPreEq::PreEqCoAdjStatus
    """

    OTHER = 1  # Any state not described below
    SUCCESS = 2  # Adjustments fully applied
    CLIPPED = 3  # Partially applied due to excessive ripple/tilt
    REJECTED = 4  # Rejected / not applied

    def __str__(self) -> str:
        return self.name.lower()


class DocsPnmCmUsPreEqFields(BaseModel):
    docsPnmCmUsPreEqFileEnable: bool
    docsPnmCmUsPreEqAmpRipplePkToPk: float
    docsPnmCmUsPreEqAmpRippleRms: float
    docsPnmCmUsPreEqAmpSlope: float
    docsPnmCmUsPreEqGrpDelayRipplePkToPk: float
    docsPnmCmUsPreEqGrpDelayRippleRms: float
    docsPnmCmUsPreEqPreEqCoAdjStatus: str
    docsPnmCmUsPreEqMeasStatus: str
    docsPnmCmUsPreEqLastUpdateFileName: str
    docsPnmCmUsPreEqFileName: str
    docsPnmCmUsPreEqAmpMean: float
    docsPnmCmUsPreEqGrpDelaySlope: float
    docsPnmCmUsPreEqGrpDelayMean: float


class DocsPnmCmUsPreEqEntry(BaseModel):
    index: int
    channel_id: ChannelId
    entry: DocsPnmCmUsPreEqFields

    @staticmethod
    def thousandth_db(value: str | int | float) -> float:
        """
        Converts a ThousandthdB value (integer or string) to a float in dB.
        Example: 12345 -> 12.345 dB
        """
        try:
            return float(value) / 1000.0
        except (ValueError, TypeError):
            return float("nan")

    @staticmethod
    def thousandth_db_per_mhz(value: str | int | float) -> float:
        """
        Converts a ThousandthdB/MHz value to a float in dB/MHz.
        Example: 12345 -> 12.345 dB/MHz
        """
        try:
            return float(value) / 1000.0
        except (ValueError, TypeError):
            return float("nan")

    @staticmethod
    def thousandth_ns(value: str | int | float) -> float:
        """
        Converts a value expressed in units of 0.001 nsec to nsec.
        Example: 12345 -> 12.345 nsec
        """
        try:
            return float(value) / 1000.0
        except (ValueError, TypeError):
            return float("nan")

    @staticmethod
    def thousandth_ns_per_mhz(value: str | int | float) -> float:
        """
        Converts a ThousandthNsec/MHz value to nsec/MHz.
        Example: 12345 -> 12.345 nsec/MHz
        """
        try:
            return float(value) / 1000.0
        except (ValueError, TypeError):
            return float("nan")

    @staticmethod
    def to_pre_eq_status(value: str | int) -> PreEqCoAdjStatus:
        """
        Converts an integer value to PreEqCoAdjStatus enum.
        """
        try:
            return PreEqCoAdjStatus(int(value))
        except (ValueError, KeyError):
            return PreEqCoAdjStatus.OTHER

    @staticmethod
    def to_pre_eq_status_str(value: str | int) -> str:
        """
        Convert integer status to a lowercase string label (e.g. 'success').
        """
        return str(DocsPnmCmUsPreEqEntry.to_pre_eq_status(value))

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsPnmCmUsPreEqEntry:
        logger = logging.getLogger(cls.__name__)

        async def fetch(
            oid: str, cast_fn: Callable[[object], T] | None = None
        ) -> T | object | None:
            try:
                result = await snmp.get(f"{oid}.{index}")
                value = Snmp_v2c.get_result_value(result)
                if value is None:
                    return None
            except Exception as e:
                logger.warning("Fetch error for %s.%s: %s", oid, index, e)
                return None
                return None

        fields = DocsPnmCmUsPreEqFields(
            docsPnmCmUsPreEqFileEnable=await fetch(
                "docsPnmCmUsPreEqFileEnable", Snmp_v2c.truth_value
            ),
            docsPnmCmUsPreEqAmpRipplePkToPk=await fetch(
                "docsPnmCmUsPreEqAmpRipplePkToPk", cls.thousandth_db
            ),
            docsPnmCmUsPreEqAmpRippleRms=await fetch(
                "docsPnmCmUsPreEqAmpRippleRms", cls.thousandth_db
            ),
            docsPnmCmUsPreEqAmpSlope=await fetch(
                "docsPnmCmUsPreEqAmpSlope", cls.thousandth_db_per_mhz
            ),
            docsPnmCmUsPreEqGrpDelayRipplePkToPk=await fetch(
                "docsPnmCmUsPreEqGrpDelayRipplePkToPk", cls.thousandth_ns
            ),
            docsPnmCmUsPreEqGrpDelayRippleRms=await fetch(
                "docsPnmCmUsPreEqGrpDelayRippleRms", cls.thousandth_ns
            ),
            docsPnmCmUsPreEqPreEqCoAdjStatus=await fetch(
                "docsPnmCmUsPreEqPreEqCoAdjStatus", cls.to_pre_eq_status_str
            ),
            docsPnmCmUsPreEqMeasStatus=await fetch(
                "docsPnmCmUsPreEqMeasStatus", measurement_status
            ),
            docsPnmCmUsPreEqLastUpdateFileName=await fetch(
                "docsPnmCmUsPreEqLastUpdateFileName", str
            ),
            docsPnmCmUsPreEqFileName=await fetch("docsPnmCmUsPreEqFileName", str),
            docsPnmCmUsPreEqAmpMean=await fetch(
                "docsPnmCmUsPreEqAmpMean", cls.thousandth_db
            ),
            docsPnmCmUsPreEqGrpDelaySlope=await fetch(
                "docsPnmCmUsPreEqGrpDelaySlope", cls.thousandth_ns_per_mhz
            ),
            docsPnmCmUsPreEqGrpDelayMean=await fetch(
                "docsPnmCmUsPreEqGrpDelayMean", cls.thousandth_ns
            ),
        )

        channel_id = await fetch(
            "docsIf31CmUsOfdmaChanChannelId", ChannelId
        ) or ChannelId(index)
        return cls(index=index, channel_id=channel_id, entry=fields)

    @classmethod
    async def get(
        cls, snmp: Snmp_v2c, indices: list[int]
    ) -> list[DocsPnmCmUsPreEqEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsPnmCmUsPreEqEntry] = []

        async def fetch_entry(idx: int) -> DocsPnmCmUsPreEqEntry | None:
            try:
                return await cls.from_snmp(idx, snmp)
            except Exception as e:
                logger.warning(
                    "Failed to fetch US PreEq entry for index %s: %s", idx, e
                )
                return None

        for idx in indices:
            entry = await fetch_entry(idx)
            if entry is not None:
                results.append(entry)

        return results
