## Agent Review Bundle Summary
- Goal: Convert docsIf31CmDsOfdmChanChanIndicator to string values via a shared enum.
- Changes: Added DocsIf31CmDsOfdmChanIndicator enum, normalized channel indicator output to strings, updated docs, and added tests.
- Files: src/pypnm/lib/constants.py, src/pypnm/docsis/data_type/DocsIf31CmDsOfdmChanEntry.py, docs/api/fast-api/single/ds/ofdm/channel-stats.md, tests/test_docs_if31_cm_ds_ofdm_chan_indicator.py
- Tests: ruff check src; pytest -q
- Notes: Used ruff import fix for DocsIf31CmDsOfdmChanEntry.py to satisfy import sorting; hardware SNMP integration tests skipped (PNM_CM_IT not set).

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

class DocsIf3CmStatusUsRangingStatus(StringEnum):
    OTHER = "other"
    ABORTED = "aborted"
    RETRIES_EXCEEDED = "retriesExceeded"
    SUCCESS = "success"
    CONTINUE = "continue"
    TIMEOUT_T4 = "timeoutT4"

    @classmethod
    def from_int(cls, value: int | None) -> DocsIf3CmStatusUsRangingStatus | None:
        if value is None:
            return None
        match value:
            case 1:
                return cls.OTHER
            case 2:
                return cls.ABORTED
            case 3:
                return cls.RETRIES_EXCEEDED
            case 4:
                return cls.SUCCESS
            case 5:
                return cls.CONTINUE
            case 6:
                return cls.TIMEOUT_T4
            case _:
                return None

class DocsIf31CmDsOfdmChanIndicator(StringEnum):
    OTHER = "other"
    PRIMARY = "primary"
    BACKUP_PRIMARY = "backupPrimary"
    NON_PRIMARY = "nonPrimary"

    @classmethod
    def from_int(cls, value: int | None) -> DocsIf31CmDsOfdmChanIndicator | None:
        if value is None:
            return None
        match value:
            case 1:
                return cls.OTHER
            case 2:
                return cls.PRIMARY
            case 3:
                return cls.BACKUP_PRIMARY
            case 4:
                return cls.NON_PRIMARY
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
    "DocsIf3CmStatusUsRangingStatus",
    "DocsIf31CmDsOfdmChanIndicator",
    "DEFAULT_SPECTRUM_ANALYZER_INDICES",
    "FEC_SUMMARY_TYPE_STEP_SECONDS", "FEC_SUMMARY_TYPE_LABEL",
]

# FILE: src/pypnm/docsis/data_type/DocsIf31CmDsOfdmChanEntry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import (
    INVALID_CHANNEL_ID,
    KHZ,
    DocsIf31CmDsOfdmChanIndicator,
)
from pypnm.lib.types import ChannelId, FrequencyHz
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIf31CmDsOfdmChanEntry(BaseModel):
    """
    DOCSIS 3.1 CM Downstream OFDM Channel attributes (docsIf31CmDsOfdmChanTable).

    Notes
    -----
    - All values are retrieved via symbolic OIDs (no compiled OIDs).
    - Presence of fields depends on device/MIB support.
    """
    docsIf31CmDsOfdmChanChannelId:                ChannelId = INVALID_CHANNEL_ID
    docsIf31CmDsOfdmChanChanIndicator:            DocsIf31CmDsOfdmChanIndicator | None = None
    docsIf31CmDsOfdmChanSubcarrierZeroFreq:       FrequencyHz | None = None
    docsIf31CmDsOfdmChanFirstActiveSubcarrierNum: int | None = None
    docsIf31CmDsOfdmChanLastActiveSubcarrierNum:  int | None = None
    docsIf31CmDsOfdmChanNumActiveSubcarriers:     int | None = None
    docsIf31CmDsOfdmChanSubcarrierSpacing:        int | None = None
    docsIf31CmDsOfdmChanCyclicPrefix:             int | None = None
    docsIf31CmDsOfdmChanRollOffPeriod:            int | None = None
    docsIf31CmDsOfdmChanPlcFreq:                  FrequencyHz | None = None
    docsIf31CmDsOfdmChanNumPilots:                int | None = None
    docsIf31CmDsOfdmChanTimeInterleaverDepth:     int | None = None
    docsIf31CmDsOfdmChanPlcTotalCodewords:        int | None = None
    docsIf31CmDsOfdmChanPlcUnreliableCodewords:   int | None = None
    docsIf31CmDsOfdmChanNcpTotalFields:           int | None = None
    docsIf31CmDsOfdmChanNcpFieldCrcFailures:      int | None = None


class DocsIf31CmDsOfdmChanChannelEntry(BaseModel):
    """
    Container for a single downstream OFDM channel record retrieved via SNMP.

    Attributes
    ----------
    index : int
        Table index used to query SNMP (instance suffix).
    channel_id : int
        Mirrored from ``docsIf31CmDsOfdmChanChannelId``; 0 if absent.
    entry : DocsIf31CmDsOfdmChanEntry
        Populated OFDM channel attributes for this index.
    """
    index: int
    channel_id: int
    entry: DocsIf31CmDsOfdmChanEntry

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIf31CmDsOfdmChanChannelEntry:
        logger = logging.getLogger(cls.__name__)

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

                if cast is not None:
                    return safe_cast(val, cast)

                s = str(val).strip()
                if s.isdigit():
                    return int(s)
                if s.lower() in ("true", "false"):
                    return s.lower() == "true"
                try:
                    return float(s)
                except ValueError:
                    return s
            except Exception as e:
                logger.warning(f"Failed to fetch {field}.{index}: {e}")
                return None

        entry = DocsIf31CmDsOfdmChanEntry(
            docsIf31CmDsOfdmChanChannelId                 = await fetch("docsIf31CmDsOfdmChanChannelId", ChannelId),
            docsIf31CmDsOfdmChanChanIndicator             = DocsIf31CmDsOfdmChanIndicator.from_int(
                await fetch("docsIf31CmDsOfdmChanChanIndicator", int),
            ),
            docsIf31CmDsOfdmChanSubcarrierZeroFreq        = await fetch("docsIf31CmDsOfdmChanSubcarrierZeroFreq", FrequencyHz),
            docsIf31CmDsOfdmChanFirstActiveSubcarrierNum  = await fetch("docsIf31CmDsOfdmChanFirstActiveSubcarrierNum", int),
            docsIf31CmDsOfdmChanLastActiveSubcarrierNum   = await fetch("docsIf31CmDsOfdmChanLastActiveSubcarrierNum", int),
            docsIf31CmDsOfdmChanNumActiveSubcarriers      = await fetch("docsIf31CmDsOfdmChanNumActiveSubcarriers", int),
            docsIf31CmDsOfdmChanSubcarrierSpacing         = await fetch("docsIf31CmDsOfdmChanSubcarrierSpacing", int) * KHZ,
            docsIf31CmDsOfdmChanCyclicPrefix              = await fetch("docsIf31CmDsOfdmChanCyclicPrefix", int),
            docsIf31CmDsOfdmChanRollOffPeriod             = await fetch("docsIf31CmDsOfdmChanRollOffPeriod", int),
            docsIf31CmDsOfdmChanPlcFreq                   = await fetch("docsIf31CmDsOfdmChanPlcFreq", FrequencyHz),
            docsIf31CmDsOfdmChanNumPilots                 = await fetch("docsIf31CmDsOfdmChanNumPilots", int),
            docsIf31CmDsOfdmChanTimeInterleaverDepth      = await fetch("docsIf31CmDsOfdmChanTimeInterleaverDepth", int),
            docsIf31CmDsOfdmChanPlcTotalCodewords         = await fetch("docsIf31CmDsOfdmChanPlcTotalCodewords", int),
            docsIf31CmDsOfdmChanPlcUnreliableCodewords    = await fetch("docsIf31CmDsOfdmChanPlcUnreliableCodewords", int),
            docsIf31CmDsOfdmChanNcpTotalFields            = await fetch("docsIf31CmDsOfdmChanNcpTotalFields", int),
            docsIf31CmDsOfdmChanNcpFieldCrcFailures       = await fetch("docsIf31CmDsOfdmChanNcpFieldCrcFailures", int),
        )

        return cls(
            index      = index,
            channel_id = entry.docsIf31CmDsOfdmChanChannelId or 0,
            entry      = entry
        )

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf31CmDsOfdmChanChannelEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsIf31CmDsOfdmChanChannelEntry] = []

        if not indices:
            logger.warning("No OFDM channel indices provided.")
            return results

        for i in indices:
            entry = await cls.from_snmp(i, snmp)
            if entry.entry.docsIf31CmDsOfdmChanChannelId != INVALID_CHANNEL_ID:
                results.append(entry)
            else:
                logger.warning(f"Failed to retrieve OFDM channel {i}: invalid channel ID")

        return results

    # NEW: entries-only helper to accommodate your existing method signature.
    @classmethod
    async def get_entries(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf31CmDsOfdmChanEntry]:
        """
        Convenience wrapper that returns only the `DocsIf31CmDsOfdmChanEntry`
        objects (no channel wrapper), preserving a return type of
        `List[DocsIf31CmDsOfdmChanEntry]`.

        This is intended to fit code like:
            await self.getDocsIf31CmDsOfdmChanEntry() -> List[DocsIf31CmDsOfdmChanEntry]
        """
        wrappers = await cls.get(snmp, indices)
        return [w.entry for w in wrappers]

# FILE: docs/api/fast-api/single/ds/ofdm/channel-stats.md
# DOCSIS 3.1 Downstream OFDM Channel Statistics

Fetches Downstream OFDM Channel Configuration And Performance Data From A DOCSIS 3.1 Cable Modem Using SNMP.

## Endpoint

**POST** `/docs/if31/ds/ofdm/channel/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../common/request.md)
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../common/response.md) (`mac_address`, `status`, `message`, `data`).

`data` is an **array** of downstream OFDM channels. Each item contains the SNMP table `index`, the `channel_id`, and an `entry` with DS-OFDM configuration and statistics.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": [
    {
      "index": 48,
      "channel_id": 34,
      "entry": {
        "docsIf31CmDsOfdmChanChanIndicator": "nonPrimary",
        "docsIf31CmDsOfdmChanSubcarrierZeroFreq": 847100000,
        "docsIf31CmDsOfdmChanFirstActiveSubcarrierNum": 1238,
        "docsIf31CmDsOfdmChanLastActiveSubcarrierNum": 2857,
        "docsIf31CmDsOfdmChanNumActiveSubcarriers": 1583,
        "docsIf31CmDsOfdmChanSubcarrierSpacing": 50,
        "docsIf31CmDsOfdmChanCyclicPrefix": 512,
        "docsIf31CmDsOfdmChanRollOffPeriod": 256,
        "docsIf31CmDsOfdmChanPlcFreq": 954000000,
        "docsIf31CmDsOfdmChanNumPilots": 29,
        "docsIf31CmDsOfdmChanTimeInterleaverDepth": 16,
        "docsIf31CmDsOfdmChanPlcTotalCodewords": 264684790,
        "docsIf31CmDsOfdmChanPlcUnreliableCodewords": 0,
        "docsIf31CmDsOfdmChanNcpTotalFields": 3387947050,
        "docsIf31CmDsOfdmChanNcpFieldCrcFailures": 0
      }
    },
    {
      "index": 49,
      "channel_id": 33,
      "entry": {
        "docsIf31CmDsOfdmChanChanIndicator": "nonPrimary",
        "docsIf31CmDsOfdmChanSubcarrierZeroFreq": 758600000,
        "docsIf31CmDsOfdmChanFirstActiveSubcarrierNum": 1148,
        "docsIf31CmDsOfdmChanLastActiveSubcarrierNum": 2947,
        "docsIf31CmDsOfdmChanNumActiveSubcarriers": 1761,
        "docsIf31CmDsOfdmChanSubcarrierSpacing": 50,
        "docsIf31CmDsOfdmChanCyclicPrefix": 512,
        "docsIf31CmDsOfdmChanRollOffPeriod": 256,
        "docsIf31CmDsOfdmChanPlcFreq": 861000000,
        "docsIf31CmDsOfdmChanNumPilots": 31,
        "docsIf31CmDsOfdmChanTimeInterleaverDepth": 16,
        "docsIf31CmDsOfdmChanPlcTotalCodewords": 264688869,
        "docsIf31CmDsOfdmChanPlcUnreliableCodewords": 0,
        "docsIf31CmDsOfdmChanNcpTotalFields": 3387999936,
        "docsIf31CmDsOfdmChanNcpFieldCrcFailures": 0
      }
    }
  ]
}
```

## Channel Fields

| Field        | Type | Description                                                                            |
| ------------ | ---- | -------------------------------------------------------------------------------------- |
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table.            |
| `channel_id` | int  | DOCSIS downstream OFDM logical channel ID.                                             |
| `entry`      | obj  | DS-OFDM configuration and counters for the channel (see next table for field details). |

## Entry Fields

| Field                                          | Type | Units | Description                                                      |
| ---------------------------------------------- | ---- | ----- | ---------------------------------------------------------------- |
| `docsIf31CmDsOfdmChanChanIndicator`            | string | —   | Channel indicator (e.g., `primary`, `backupPrimary`, `nonPrimary`). |
| `docsIf31CmDsOfdmChanSubcarrierZeroFreq`       | int  | Hz    | Frequency of subcarrier **0**.                                   |
| `docsIf31CmDsOfdmChanFirstActiveSubcarrierNum` | int  | —     | Index of the first active subcarrier.                            |
| `docsIf31CmDsOfdmChanLastActiveSubcarrierNum`  | int  | —     | Index of the last active subcarrier.                             |
| `docsIf31CmDsOfdmChanNumActiveSubcarriers`     | int  | —     | Count of active subcarriers.                                     |
| `docsIf31CmDsOfdmChanSubcarrierSpacing`        | int  | kHz   | Subcarrier spacing (typical downstream values are 25 or 50 kHz). |
| `docsIf31CmDsOfdmChanCyclicPrefix`             | int  | samp  | Cyclic prefix length in samples.                                 |
| `docsIf31CmDsOfdmChanRollOffPeriod`            | int  | samp  | Roll-off (guard) period in samples.                              |
| `docsIf31CmDsOfdmChanPlcFreq`                  | int  | Hz    | PLC (Physical Link Channel) center frequency.                    |
| `docsIf31CmDsOfdmChanNumPilots`                | int  | —     | Number of pilot subcarriers.                                     |
| `docsIf31CmDsOfdmChanTimeInterleaverDepth`     | int  | sym   | Time interleaver depth in OFDM symbols.                          |
| `docsIf31CmDsOfdmChanPlcTotalCodewords`        | int  | —     | Total PLC codewords received.                                    |
| `docsIf31CmDsOfdmChanPlcUnreliableCodewords`   | int  | —     | PLC codewords flagged as unreliable.                             |
| `docsIf31CmDsOfdmChanNcpTotalFields`           | int  | —     | Total NCP (Next Codeword Pointer) fields received.               |
| `docsIf31CmDsOfdmChanNcpFieldCrcFailures`      | int  | —     | NCP fields with CRC failures.                                    |

## Notes

* Useful for visualizing OFDM channel characteristics and error metrics for proactive diagnostics.
* Ensure SNMP access to the modem’s `ip_address` from your collection host.
* Field names align with `DOCSIS-IF3-MIB` DS-OFDM channel objects.

# FILE: tests/test_docs_if31_cm_ds_ofdm_chan_indicator.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIf31CmDsOfdmChanEntry import DocsIf31CmDsOfdmChanChannelEntry
from pypnm.lib.constants import DocsIf31CmDsOfdmChanIndicator
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    async def get(self, oid: str) -> tuple[str, str]:
        return (oid, self._values.get(oid, ""))


@pytest.mark.asyncio
async def test_docs_if31_cm_ds_ofdm_chan_indicator_maps_nonprimary(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "docsIf31CmDsOfdmChanChanIndicator.1": "4",
        "docsIf31CmDsOfdmChanChannelId.1": "1",
        "docsIf31CmDsOfdmChanSubcarrierSpacing.1": "25",
    }

    fake = _FakeSnmp(values)
    monkeypatch.setattr(Snmp_v2c, "get_result_value", lambda res: res[1])

    result = await DocsIf31CmDsOfdmChanChannelEntry.from_snmp(1, fake)
    assert result.entry.docsIf31CmDsOfdmChanChanIndicator == DocsIf31CmDsOfdmChanIndicator.NON_PRIMARY

