## Agent Review Bundle Summary
- Goal: Centralize TenthdB casting for RxMER and reuse in downstream channel parsing.
- Changes: Added tenthdB cast helper and switched RxMER scaling to use it.
- Files: src/pypnm/snmp/casts.py, src/pypnm/docsis/data_type/DocsIfDownstreamChannel.py
- Tests: ruff check src; pytest -q
- Notes: Hardware SNMP integration tests skipped (PNM_CM_IT not set).

# FILE: src/pypnm/snmp/casts.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from pypnm.docsis.data_type.enums import MeasStatusType
from pypnm.lib.types import ScalarValue


def measurement_status(v: ScalarValue) -> str:
    """
    Return The Measurement Status Name For A Numeric Code.

    Attempts To Interpret ``v`` As An Integer And Map It To
    ``MeasStatusType``. If Conversion Or Import Fails, ``"other"``
    Is Returned As A Fallback.
    """
    try:
        code = int(v)
        return str(MeasStatusType(code))
    except (ValueError, TypeError):
        return "other"
    except ImportError:
        return "other"


def as_bool(v: ScalarValue) -> bool:
    """
    Convert A Scalar Value To Bool With Integer Preference.

    The Function First Attempts To Interpret ``v`` As An Integer
    And Uses ``bool(int(v))``. If That Fails, It Falls Back To
    Python's Native ``bool(v)`` Semantics.
    """
    try:
        return bool(int(v))
    except (ValueError, TypeError):
        return bool(v)


def as_int(v: ScalarValue) -> int:
    """
    Convert A Scalar Value To Int.

    This Is A Thin Wrapper Around ``int(v)`` To Provide A
    Consistent Conversion Surface For SNMP And Parser Helpers.
    """
    return int(v)


def as_str(v: ScalarValue) -> str:
    """
    Convert A Scalar Value To Str.

    Ensures All SNMP/Parser Scalars Can Be Safely Rendered
    As Text Without Relying On Implicit Conversions.
    """
    return str(v)


def as_float0(v: ScalarValue) -> float:
    """
    Convert A Scalar Value To Float Without Scaling.

    This Is Typically Used For Values That Are Already
    In Engineering Units And Do Not Require Fixed-Point
    Normalization.
    """
    return float(v)


def as_float2(v: ScalarValue, /) -> float:
    """
    Convert A Fixed-Point Scalar To A Two-Decimal Float.

    SNMP Often Encodes Values In 1/100 Units. This Helper
    Divides By ``100.0`` And Rounds To Two Decimal Places.
    """
    return round(float(v) / 100.0, 2)


def scale(v: ScalarValue, *, factor: float, ndigits: int | None = None) -> float:
    """
    Scale A Scalar Value By A Factor With Optional Rounding.

    Parameters
    ----------
    v:
        Input Scalar To Be Converted To ``float`` Before Scaling.
    factor:
        Multiplicative Scale Factor (For Example, 0.001 For
        Thousandths Or 0.1 For Tenths).
    ndigits:
        Optional Number Of Decimal Places For ``round``. When
        ``None``, No Rounding Is Applied.

    Returns
    -------
    float
        The Scaled (And Optionally Rounded) Value.
    """
    x = float(v) * factor
    return round(x, ndigits) if ndigits is not None else x


def per_hundred(v: ScalarValue, *, ndigits: int = 2) -> float:
    """
    Normalize A Scalar Expressed In 1/100 Units.

    Divides ``v`` By ``100.0`` And Rounds To ``ndigits`` Decimal
    Places. Commonly Used For Percentage-Like Fixed-Point Fields.
    """
    return round(float(v) / 100.0, ndigits)


def per_thousand(v: ScalarValue, *, ndigits: int = 3) -> float:
    """
    Normalize A Scalar Expressed In 1/1000 Units.

    Generic Helper For MIB Units Expressed In 0.001 Steps
    (ThousandthdB, ThousandthNsec, ThousandthdB/MHz,
    ThousandthNsec/MHz). Divides ``v`` By ``1000.0`` And
    Rounds To ``ndigits`` Decimal Places.
    """
    return round(float(v) / 1000.0, ndigits)


def tenthdB(v: ScalarValue, *, ndigits: int = 1) -> float:
    """
    Normalize A Scalar Expressed In Tenths Of A dB.

    Divides ``v`` By ``10.0`` And Rounds To ``ndigits`` Decimal
    Places. Used For MIB fields that are defined as TenthdB.
    """
    return round(float(v) / 10.0, ndigits)

# FILE: src/pypnm/docsis/data_type/DocsIfDownstreamChannel.py
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import INVALID_CHANNEL_ID
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
    docsIfDownChannelModulation : Optional[int]
        Modulation enum value, from ``docsIfDownChannelModulation``.
    docsIfDownChannelInterleave : Optional[int]
        Interleave depth/setting, from ``docsIfDownChannelInterleave``.
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
    docsIfDownChannelModulation: int | None = None
    docsIfDownChannelInterleave: int | None = None
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
            docsIfDownChannelModulation =   await fetch("docsIfDownChannelModulation", int),
            docsIfDownChannelInterleave =   await fetch("docsIfDownChannelInterleave", int),
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

