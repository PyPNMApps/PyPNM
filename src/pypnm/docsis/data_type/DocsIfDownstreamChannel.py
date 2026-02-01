# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import (
    INVALID_CHANNEL_ID,
    DocsIfDownChannelInterleave,
    DocsIfDownChannelModulation,
)
from pypnm.lib.types import ChannelId, FrequencyHz
from pypnm.snmp.casts import tenthdB
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIfDownstreamEntry(BaseModel):
    """
    DOCSIS downstream SC-QAM signal/quality metrics for a single channel.

    Notes
    -----
    - Values are sourced from symbolic OIDs in DOCSIS-IF(-EXT3)-MIB (e.g.,
      ``docsIfDownChannelId``, ``docsIfSigQCorrecteds``, etc.).
    - ``docsIfDownChannelPower`` is converted from tenths-of-dBmV (SNMP integer)
      to a float in dBmV.
    - Presence of fields depends on CM/CMTS support and MIB implementation.

    Attributes
    ----------
    docsIfDownChannelId : Optional[int]
        Channel ID (SC-QAM), from ``docsIfDownChannelId``.
    docsIfDownChannelFrequency : Optional[int]
        Center frequency in Hz, from ``docsIfDownChannelFrequency``.
    docsIfDownChannelWidth : Optional[int]
        Channel width in Hz, from ``docsIfDownChannelWidth``.
    docsIfDownChannelModulation : Optional[str]
        Modulation name, from ``docsIfDownChannelModulation``.
    docsIfDownChannelInterleave : Optional[str]
        Interleave mode name, from ``docsIfDownChannelInterleave``.
    docsIfDownChannelPower : Optional[float]
        Average channel power in dBmV (float), converted from tenths-of-dBmV.
    docsIfSigQUnerroreds : Optional[int]
        Legacy unerrored codewords, from ``docsIfSigQUnerroreds``.
    docsIfSigQCorrecteds : Optional[int]
        Corrected codewords, from ``docsIfSigQCorrecteds``.
    docsIfSigQUncorrectables : Optional[int]
        Uncorrectable codewords, from ``docsIfSigQUncorrectables``.
    docsIfSigQMicroreflections : Optional[int]
        Micro-reflections metric, from ``docsIfSigQMicroreflections``.
    docsIfSigQExtUnerroreds : Optional[int]
        Extended unerrored codewords, from ``docsIfSigQExtUnerroreds``.
    docsIfSigQExtCorrecteds : Optional[int]
        Extended corrected codewords, from ``docsIfSigQExtCorrecteds``.
    docsIfSigQExtUncorrectables : Optional[int]
        Extended uncorrectable codewords, from ``docsIfSigQExtUncorrectables``.
    docsIf3SignalQualityExtRxMER : Optional[float]
        Extended RxMER (dB), from ``docsIf3SignalQualityExtRxMER``.
    """
    docsIfDownChannelId: ChannelId = INVALID_CHANNEL_ID
    docsIfDownChannelFrequency: FrequencyHz | None = None
    docsIfDownChannelWidth: FrequencyHz | None = None
    docsIfDownChannelModulation: DocsIfDownChannelModulation | None = None
    docsIfDownChannelInterleave: DocsIfDownChannelInterleave | None = None
    docsIfDownChannelPower: float | None = None
    docsIfSigQUnerroreds: int | None = None
    docsIfSigQCorrecteds: int | None = None
    docsIfSigQUncorrectables: int | None = None
    docsIfSigQMicroreflections: int | None = None
    docsIfSigQExtUnerroreds: int | None = None
    docsIfSigQExtCorrecteds: int | None = None
    docsIfSigQExtUncorrectables: int | None = None
    docsIf3SignalQualityExtRxMER: float | None = None


class DocsIfDownstreamChannelEntry(BaseModel):
    """
    Container for a single downstream SC-QAM channel record retrieved via SNMP.

    Attributes
    ----------
    index : int
        Table index used to query SNMP (e.g., the instance suffix).
    channel_id : int
        The channel ID mirrored from the retrieved entry (0 if missing).
    entry : DocsIfDownstreamEntry
        The populated downstream metrics for the given index.

    Examples
    --------
    Basic one-off fetch:

    >>> snmp = Snmp_v2c(host="192.168.0.100", community="public", timeout=2.0, retries=1)
    >>> entry = await DocsIfDownstreamChannelEntry.from_snmp(index=1, snmp=snmp)
    >>> entry.channel_id
    1

    Batch fetch for multiple indices:

    >>> indices = [1, 2, 3, 4]
    >>> entries = await DocsIfDownstreamChannelEntry.get(snmp, indices)
    >>> len(entries)
    4
    """
    index: int
    channel_id: int
    entry: DocsIfDownstreamEntry

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIfDownstreamChannelEntry:
        """
        Build an instance by querying SNMP for a single downstream SC-QAM index.

        Parameters
        ----------
        index : int
            The SNMP table index (instance) to query (e.g., ``docsIfDownChannelId.<index>``).
        snmp : Snmp_v2c
            Initialized SNMP v2c client used to perform ``GET`` operations.

        Returns
        -------
        DocsIfDownstreamChannelEntry
            A populated channel container with metrics under ``entry`` and
            ``channel_id`` mirrored from ``docsIfDownChannelId`` (or 0 if absent).

        Notes
        -----
        - Uses symbolic OIDs (no compiled numeric OIDs required).
        - Gracefully handles missing/invalid values; non-parsable fields become ``None``.
        - ``docsIfDownChannelPower`` is converted from tenths-of-dBmV to float dBmV.

        Examples
        --------
        >>> snmp = Snmp_v2c(host="192.168.0.100", community="public")
        >>> result = await DocsIfDownstreamChannelEntry.from_snmp(5, snmp)
        >>> result.entry.docsIf3SignalQualityExtRxMER  # may be None if unsupported
        """
        logger = logging.getLogger(cls.__name__)

        def tenthdBmV_to_float(value: str) -> float | None:
            try:
                return float(value) / 10.0
            except Exception:
                return None


        def to_float(value: str) -> float | None:
            try:
                return float(value)
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
                logger.warning(f"Failed to fetch {field}.{index}: {e}")
                return None

        entry = DocsIfDownstreamEntry(
            docsIfDownChannelId         =   await fetch("docsIfDownChannelId", int),
            docsIfDownChannelFrequency  =   await fetch("docsIfDownChannelFrequency", int),
            docsIfDownChannelWidth      =   await fetch("docsIfDownChannelWidth", int),
            docsIfDownChannelModulation =   DocsIfDownChannelModulation.from_int(
                await fetch("docsIfDownChannelModulation", int),
            ),
            docsIfDownChannelInterleave =   DocsIfDownChannelInterleave.from_int(
                await fetch("docsIfDownChannelInterleave", int),
            ),
            docsIfDownChannelPower      =   await fetch("docsIfDownChannelPower", tenthdBmV_to_float),
            docsIfSigQUnerroreds        =   await fetch("docsIfSigQUnerroreds", int),
            docsIfSigQCorrecteds        =   await fetch("docsIfSigQCorrecteds", int),
            docsIfSigQUncorrectables    =   await fetch("docsIfSigQUncorrectables", int),
            docsIfSigQMicroreflections  =   await fetch("docsIfSigQMicroreflections", int),
            docsIfSigQExtUnerroreds     =   await fetch("docsIfSigQExtUnerroreds", int),
            docsIfSigQExtCorrecteds     =   await fetch("docsIfSigQExtCorrecteds", int),
            docsIfSigQExtUncorrectables =   await fetch("docsIfSigQExtUncorrectables", int),
            docsIf3SignalQualityExtRxMER =  await fetch("docsIf3SignalQualityExtRxMER", tenthdB)
        )


        return cls(
            index=index,
            channel_id=entry.docsIfDownChannelId or 0,
            entry=entry
        )

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIfDownstreamChannelEntry]:
        """
        Fetch multiple downstream SC-QAM entries in a single call.

        Parameters
        ----------
        snmp : Snmp_v2c
            Initialized SNMP v2c client.
        indices : List[int]
            Table indices (instances) to retrieve.

        Returns
        -------
        List[DocsIfDownstreamChannelEntry]
            A list of populated entries. If ``indices`` is empty or any index
            fails to fetch, the method logs a warning and continues.

        Examples
        --------
        >>> snmp = Snmp_v2c(host="192.168.0.100", community="public")
        >>> entries = await DocsIfDownstreamChannelEntry.get(snmp, [1, 2, 3])
        >>> [e.channel_id for e in entries]
        [1, 2, 3]
        """
        logger = logging.getLogger(cls.__name__)
        results: list[DocsIfDownstreamChannelEntry] = []

        if not indices:
            logger.warning("No downstream SC-QAM channel indices provided.")
            return results

        for index in indices:
            try:
                result = await cls.from_snmp(index, snmp)
                results.append(result)
            except Exception as e:  # noqa: PERF203
                logger.warning(f"Failed to retrieve downstream channel {index}: {e}")

        return results
