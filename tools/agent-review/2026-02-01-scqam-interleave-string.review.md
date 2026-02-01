## Agent Review Bundle Summary
- Goal: Convert SC-QAM docsIfDownChannelInterleave to string values via a shared enum.
- Changes: Added DocsIfDownChannelInterleave enum, normalized interleave output to strings, updated docs, and added tests.
- Files: src/pypnm/lib/constants.py, src/pypnm/docsis/data_type/DocsIfDownstreamChannel.py, docs/api/fast-api/single/ds/scqam/channel-stats.md, tests/test_docs_if_down_channel_interleave.py
- Tests: ruff check src; pytest -q
- Notes: Used ruff import fix for DocsIfDownstreamChannel.py to satisfy import sorting; hardware SNMP integration tests skipped (PNM_CM_IT not set).

# FILE: src/pypnm/lib/constants.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026

from __future__ import annotations

from typing import Final, Literal, TypeAlias, TypeVar, cast

from pypnm.lib.types import (
    STATUS,
    CaptureTime,
    ChannelId,
    FloatEnum,
    FrequencyHz,
    Number,
    ProfileId,
    StringEnum,
)

DEFAULT_SSH_PORT: int   = 22

HZ:  Final[int] = 1
KHZ: Final[int] = 1_000
MHZ: Final[int] = 1_000_000
GHZ: Final[int] = 1_000_000_000

FEET_PER_METER: Final[float] = 3.280839895013123
SPEED_OF_LIGHT: Final[float] = 299_792_458.0  # m/s

NULL_ARRAY_NUMBER: Final[list[Number]] = [0]

ZERO_FREQUENCY: Final[FrequencyHz]                  = cast(FrequencyHz, 0)

INVALID_CHANNEL_ID: Final[ChannelId]                = cast(ChannelId, -1)
INVALID_PROFILE_ID: Final[ProfileId]                = cast(ProfileId, -1)
INVALID_SUB_CARRIER_ZERO_FREQ: Final[FrequencyHz]   = cast(FrequencyHz, 0)
INVALID_START_VALUE: Final[int]                     = -1
INVALID_SCHEMA_TYPE: Final[int]                     = -1
INVALID_CAPTURE_TIME: Final[CaptureTime]            = cast(CaptureTime, -1)

DEFAULT_CAPTURE_TIME: Final[CaptureTime]            = cast(CaptureTime, 19700101)  # epoch start

CableTypes: TypeAlias = Literal["RG6", "RG59", "RG11"]

DOCSIS_ROLL_OFF_FACTOR: Final[float] = 0.25

# Velocity Factor (VF) by cable type (fraction of c0)
CABLE_VF: Final[dict[CableTypes, float]] = {
    "RG6":  0.85,
    "RG59": 0.82,
    "RG11": 0.87,
}

class CableType(FloatEnum):
    RG6  = 0.85
    RG59 = 0.82
    RG11 = 0.87

class MediaType(StringEnum):
    """
    Canonical Media Type Enumeration Used For File And HTTP Responses.

    Values
    ------
    APPLICATION_JSON
        JSON payloads (FastAPI JSONResponse, .json files).
    APPLICATION_ZIP
        ZIP archives (analysis bundles, multi-file exports).
    APPLICATION_OCTET_STREAM
        Raw binary streams (PNM files, generic downloads).
    TEXT_CSV
        Comma-separated values (tabular exports).
    """

    APPLICATION_JSON         = "application/json"
    APPLICATION_ZIP          = "application/zip"
    APPLICATION_OCTET_STREAM = "application/octet-stream"
    TEXT_CSV                 = "text/csv"

class DocsIfDownChannelModulation(StringEnum):
    UNKNOWN = "unknown"
    OTHER   = "other"
    QAM64   = "qam64"
    QAM256  = "qam256"

    @classmethod
    def from_int(cls, value: int | None) -> DocsIfDownChannelModulation | None:
        if value is None:
            return None
        match value:
            case 1:
                return cls.UNKNOWN
            case 2:
                return cls.OTHER
            case 3:
                return cls.QAM64
            case 4:
                return cls.QAM256
            case _:
                return None

class DocsIfDownChannelInterleave(StringEnum):
    UNKNOWN = "unknown"
    OTHER = "other"
    TAPS8_INCREMENT16 = "taps8Increment16"
    TAPS16_INCREMENT8 = "taps16Increment8"
    TAPS32_INCREMENT4 = "taps32Increment4"
    TAPS64_INCREMENT2 = "taps64Increment2"
    TAPS128_INCREMENT1 = "taps128Increment1"
    TAPS12_INCREMENT17 = "taps12increment17"

    @classmethod
    def from_int(cls, value: int | None) -> DocsIfDownChannelInterleave | None:
        if value is None:
            return None
        match value:
            case 1:
                return cls.UNKNOWN
            case 2:
                return cls.OTHER
            case 3:
                return cls.TAPS8_INCREMENT16
            case 4:
                return cls.TAPS16_INCREMENT8
            case 5:
                return cls.TAPS32_INCREMENT4
            case 6:
                return cls.TAPS64_INCREMENT2
            case 7:
                return cls.TAPS128_INCREMENT1
            case 8:
                return cls.TAPS12_INCREMENT17
            case _:
                return None

T = TypeVar("T")

DEFAULT_SPECTRUM_ANALYZER_INDICES: Final[list[int]] = [0]


FEC_SUMMARY_TYPE_STEP_SECONDS: dict[int, int] = {
    2: 1,      # interval10min(2): 600 samples, 1 sec apart
    3: 60,     # interval24hr(3): 1440 samples, 60 sec apart
    # other(1): unknown / device-specific, do not enforce
}

FEC_SUMMARY_TYPE_LABEL: dict[int, str] = {
    1: "other",
    2: "10-minute interval (1s cadence)",
    3: "24-hour interval (60s cadence)",
}

STATUS_OK:STATUS = True
STATUS_NOK:STATUS = False

__all__ = [
    "DOCSIS_ROLL_OFF_FACTOR",
    "STATUS_OK", "STATUS_NOK",
    "DEFAULT_SSH_PORT",
    "HZ", "KHZ", "MHZ", "GHZ",
    "ZERO_FREQUENCY",
    "FEET_PER_METER", "SPEED_OF_LIGHT",
    "NULL_ARRAY_NUMBER",
    "INVALID_CHANNEL_ID", "INVALID_PROFILE_ID", "INVALID_SUB_CARRIER_ZERO_FREQ",
    "INVALID_START_VALUE", "INVALID_SCHEMA_TYPE", "INVALID_CAPTURE_TIME",
    "DEFAULT_CAPTURE_TIME",
    "CableTypes", "CABLE_VF",
    "DocsIfDownChannelModulation",
    "DocsIfDownChannelInterleave",
    "DEFAULT_SPECTRUM_ANALYZER_INDICES",
    "FEC_SUMMARY_TYPE_STEP_SECONDS", "FEC_SUMMARY_TYPE_LABEL",
]

# FILE: src/pypnm/docsis/data_type/DocsIfDownstreamChannel.py
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

# FILE: docs/api/fast-api/single/ds/scqam/channel-stats.md
# DOCSIS 3.0 Downstream SC-QAM Channel Statistics

Provides DOCSIS 3.0 Downstream SC-QAM Channel Configuration And Signal-Quality Metrics (Power, RxMER, Codeword Counters).

## Endpoint

**POST** `/docs/if30/ds/scqam/chan/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`mac_address`, `status`, `message`, `data`).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": [
    {
      "index": 52,
      "channel_id": 32,
      "entry": {
        "docsIfDownChannelId": 32,
        "docsIfDownChannelFrequency": 639000000,
        "docsIfDownChannelWidth": 6000000,
        "docsIfDownChannelModulation": "qam256",
        "docsIfDownChannelInterleave": "taps32Increment4",
        "docsIfDownChannelPower": 1.1,
        "docsIfSigQUnerroreds": 260152637,
        "docsIfSigQCorrecteds": 351,
        "docsIfSigQUncorrectables": 0,
        "docsIfSigQMicroreflections": 3,
        "docsIfSigQExtUnerroreds": 129109307889,
        "docsIfSigQExtCorrecteds": 351,
        "docsIfSigQExtUncorrectables": 0,
        "docsIf3SignalQualityExtRxMER": 403
      }
    },
    {
      "index": 53,
      "channel_id": 31,
      "entry": {
        "docsIfDownChannelId": 31,
        "docsIfDownChannelFrequency": 633000000,
        "docsIfDownChannelWidth": 6000000,
        "docsIfDownChannelModulation": "qam256",
        "docsIfDownChannelInterleave": "taps32Increment4",
        "docsIfDownChannelPower": 0.8,
        "docsIfSigQUnerroreds": 89334852,
        "docsIfSigQCorrecteds": 460,
        "docsIfSigQUncorrectables": 0,
        "docsIfSigQMicroreflections": 3,
        "docsIfSigQExtUnerroreds": 128938490104,
        "docsIfSigQExtCorrecteds": 460,
        "docsIfSigQExtUncorrectables": 0,
        "docsIf3SignalQualityExtRxMER": 409
      }
    },
    { "...": "other channels elided" }
  ]
}
```

## Channel Fields

| Field        | Type | Description                                                                 |
| ------------ | ---- | --------------------------------------------------------------------------- |
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table. |
| `channel_id` | int  | DOCSIS downstream SC-QAM logical channel ID.                                |

## Entry Fields

| Field                          | Type  | Units  | Description                                                  |
| ------------------------------ | ----- | ------ | ------------------------------------------------------------ |
| `docsIfDownChannelId`          | int   | —      | Channel ID (mirrors logical ID).                             |
| `docsIfDownChannelFrequency`   | int   | Hz     | Center frequency.                                            |
| `docsIfDownChannelWidth`       | int   | Hz     | Channel width.                                               |
| `docsIfDownChannelModulation`  | string | —      | Modulation name (e.g., `qam256`).                           |
| `docsIfDownChannelInterleave`  | string | —      | Interleaver mode name (e.g., `taps32Increment4`).            |
| `docsIfDownChannelPower`       | float | dBmV   | Received RF power level.                                     |
| `docsIfSigQUnerroreds`         | int   | cw     | Unerrored codewords (base counter).                          |
| `docsIfSigQCorrecteds`         | int   | cw     | Corrected codewords (base counter).                          |
| `docsIfSigQUncorrectables`     | int   | cw     | Uncorrectable codewords (base counter).                      |
| `docsIfSigQMicroreflections`   | int   | —      | Micro-reflections indicator (implementation-specific scale). |
| `docsIfSigQExtUnerroreds`      | int64 | cw     | Unerrored codewords (extended 64-bit), if supported.         |
| `docsIfSigQExtCorrecteds`      | int64 | cw     | Corrected codewords (extended 64-bit), if supported.         |
| `docsIfSigQExtUncorrectables`  | int64 | cw     | Uncorrectable codewords (extended 64-bit), if supported.     |
| `docsIf3SignalQualityExtRxMER` | int   | 0.1 dB | RxMER in tenths of dB (e.g., `403` → 40.3 dB).               |

## Notes

* `docsIfDownChannelModulation` is normalized to a modulation name (e.g., `qam256`).
* Prefer extended (64-bit) counters when available to avoid rollover on high-traffic channels.
* Metrics such as RxMER, Uncorrectables, And Micro-Reflections Are Critical For Diagnosing RF Impairments.
* `docsIfDownChannelInterleave` is normalized to an interleaver mode name.

# FILE: tests/test_docs_if_down_channel_interleave.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIfDownstreamChannel import DocsIfDownstreamChannelEntry
from pypnm.lib.constants import DocsIfDownChannelInterleave
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    async def get(self, oid: str) -> tuple[str, str]:
        return (oid, self._values.get(oid, ""))


@pytest.mark.asyncio
async def test_docs_if_down_channel_interleave_maps_taps32(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "docsIfDownChannelInterleave.1": "5",
        "docsIfDownChannelId.1": "1",
    }

    fake = _FakeSnmp(values)
    monkeypatch.setattr(Snmp_v2c, "get_result_value", lambda res: res[1])

    result = await DocsIfDownstreamChannelEntry.from_snmp(1, fake)
    assert result.entry.docsIfDownChannelInterleave == DocsIfDownChannelInterleave.TAPS32_INCREMENT4

