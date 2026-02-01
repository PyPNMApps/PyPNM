## Agent Review Bundle Summary
- Goal: Map OFDMA upstream ranging status to a string enum with docs and tests.
- Changes: Added DocsIf31CmStatusOfdmaUsRangingStatus enum and mapping; updated OFDMA channel entry to use enum; refreshed OFDMA stats docs example and field type; added test coverage.
- Files: src/pypnm/lib/constants.py; src/pypnm/docsis/data_type/DocsIf31CmUsOfdmaChanEntry.py; docs/api/fast-api/single/us/ofdma/stats.md; tests/test_docs_if31_cm_status_ofdma_us_ranging_status.py.
- Tests: python3 -m compileall src; ruff check src; ruff format --check . (fails: would reformat 346 files); pytest -q (3 skipped: hardware integration).
- Notes: Ruff format check failure is pre-existing formatting drift.

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

class DocsIf31CmStatusOfdmaUsRangingStatus(StringEnum):
    OTHER = "other"
    ABORTED = "aborted"
    RETRIES_EXCEEDED = "retriesExceeded"
    SUCCESS = "success"
    CONTINUE = "continue"
    TIMEOUT_T4 = "timeoutT4"

    @classmethod
    def from_int(cls, value: int | None) -> DocsIf31CmStatusOfdmaUsRangingStatus | None:
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
    "DocsIf31CmStatusOfdmaUsRangingStatus",
    "DocsIf31CmDsOfdmChanIndicator",
    "DEFAULT_SPECTRUM_ANALYZER_INDICES",
    "FEC_SUMMARY_TYPE_STEP_SECONDS", "FEC_SUMMARY_TYPE_LABEL",
]

# FILE: src/pypnm/docsis/data_type/DocsIf31CmUsOfdmaChanEntry.py

from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import DocsIf31CmStatusOfdmaUsRangingStatus
from pypnm.lib.types import ChannelId, FrequencyHz
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIf31CmUsOfdmaChan(BaseModel):
    docsIf31CmUsOfdmaChanChannelId: ChannelId | None = None
    docsIf31CmUsOfdmaChanConfigChangeCt: int | None = None
    docsIf31CmUsOfdmaChanSubcarrierZeroFreq: FrequencyHz | None = None
    docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum: int | None = None
    docsIf31CmUsOfdmaChanLastActiveSubcarrierNum: int | None = None
    docsIf31CmUsOfdmaChanNumActiveSubcarriers: int | None = None
    docsIf31CmUsOfdmaChanSubcarrierSpacing: FrequencyHz | None = None
    docsIf31CmUsOfdmaChanCyclicPrefix: int | None = None
    docsIf31CmUsOfdmaChanRollOffPeriod: int | None = None
    docsIf31CmUsOfdmaChanNumSymbolsPerFrame: int | None = None
    docsIf31CmUsOfdmaChanTxPower: float | None = None
    docsIf31CmUsOfdmaChanPreEqEnabled: bool | None = None
    docsIf31CmStatusOfdmaUsT3Timeouts: int | None = None
    docsIf31CmStatusOfdmaUsT4Timeouts: int | None = None
    docsIf31CmStatusOfdmaUsRangingAborteds: int | None = None
    docsIf31CmStatusOfdmaUsT3Exceededs: int | None = None
    docsIf31CmStatusOfdmaUsIsMuted: bool | None = None
    docsIf31CmStatusOfdmaUsRangingStatus: DocsIf31CmStatusOfdmaUsRangingStatus | None = None

class DocsIf31CmUsOfdmaChanEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsIf31CmUsOfdmaChan

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIf31CmUsOfdmaChanEntry | None:
        logger = logging.getLogger(cls.__name__)

        def tenthdBmV_to_float(value: str) -> float | None:
            try:
                return float(value) / 10.0
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
                logger.warning(f"Failed to fetch {field}: {e}")
                return None

        entry = DocsIf31CmUsOfdmaChan(
            docsIf31CmUsOfdmaChanChannelId                  =   await fetch("docsIf31CmUsOfdmaChanChannelId", int),
            docsIf31CmUsOfdmaChanConfigChangeCt             =   await fetch("docsIf31CmUsOfdmaChanConfigChangeCt", int),
            docsIf31CmUsOfdmaChanSubcarrierZeroFreq         =   await fetch("docsIf31CmUsOfdmaChanSubcarrierZeroFreq", int),
            docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum   =   await fetch("docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum", int),
            docsIf31CmUsOfdmaChanLastActiveSubcarrierNum    =   await fetch("docsIf31CmUsOfdmaChanLastActiveSubcarrierNum", int),
            docsIf31CmUsOfdmaChanNumActiveSubcarriers       =   await fetch("docsIf31CmUsOfdmaChanNumActiveSubcarriers", int),
            docsIf31CmUsOfdmaChanSubcarrierSpacing          =   await fetch("docsIf31CmUsOfdmaChanSubcarrierSpacing", int),
            docsIf31CmUsOfdmaChanCyclicPrefix               =   await fetch("docsIf31CmUsOfdmaChanCyclicPrefix", int),
            docsIf31CmUsOfdmaChanRollOffPeriod              =   await fetch("docsIf31CmUsOfdmaChanRollOffPeriod", int),
            docsIf31CmUsOfdmaChanNumSymbolsPerFrame         =   await fetch("docsIf31CmUsOfdmaChanNumSymbolsPerFrame", int),
            docsIf31CmUsOfdmaChanTxPower                    =   await fetch("docsIf31CmUsOfdmaChanTxPower", tenthdBmV_to_float),
            docsIf31CmUsOfdmaChanPreEqEnabled               =   await fetch("docsIf31CmUsOfdmaChanPreEqEnabled", Snmp_v2c.truth_value),
            docsIf31CmStatusOfdmaUsT3Timeouts               =   await fetch("docsIf31CmStatusOfdmaUsT3Timeouts", int),
            docsIf31CmStatusOfdmaUsT4Timeouts               =   await fetch("docsIf31CmStatusOfdmaUsT4Timeouts", int),
            docsIf31CmStatusOfdmaUsRangingAborteds          =   await fetch("docsIf31CmStatusOfdmaUsRangingAborteds", int),
            docsIf31CmStatusOfdmaUsT3Exceededs              =   await fetch("docsIf31CmStatusOfdmaUsT3Exceededs", int),
            docsIf31CmStatusOfdmaUsIsMuted                  =   await fetch("docsIf31CmStatusOfdmaUsIsMuted", Snmp_v2c.truth_value),
            docsIf31CmStatusOfdmaUsRangingStatus            =   DocsIf31CmStatusOfdmaUsRangingStatus.from_int(
                await fetch("docsIf31CmStatusOfdmaUsRangingStatus", int),
            )
        )

        try:
            return cls(
                index           =   index,
                channel_id      =   entry.docsIf31CmUsOfdmaChanChannelId or 0,
                entry           =   entry
            )
        except Exception as e:
            logger.warning(f"Failed to retrieve OFDMA channel {index}: {e}")
            return None

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIf31CmUsOfdmaChanEntry]:
        results: list[DocsIf31CmUsOfdmaChanEntry] = []

        for index in indices:
            result = await cls.from_snmp(index, snmp)
            if result is not None:
                results.append(result)

        return results

# FILE: docs/api/fast-api/single/us/ofdma/stats.md
# DOCSIS 3.1 Upstream OFDMA Channel Statistics

This API provides visibility into the configuration and runtime status of upstream OFDMA channels from DOCSIS 3.1 cable modems. It includes key metrics such as active subcarrier layout, transmit power, cyclic prefix configuration, and pre-equalization status. Additionally, it tracks upstream timeout counters (T3, T4) and ranging outcomes to help diagnose impairments and channel access issues.

Use this endpoint to support PNM workflows, particularly when analyzing power levels, ranging stability, and OFDMA symbol behavior under varying network conditions.

## Endpoint

**POST** `/docs/if31/us/ofdma/channel/stats`

Retrieves statistics and configuration parameters for upstream OFDMA channels from a DOCSIS 3.1 cable modem. This includes subcarrier layout, transmit power, and upstream timing-related error counters.


## Request Body (JSON)

### Request Fields

| Field          | Type   | Description                       |
| -------------- | ------ | --------------------------------- |
| `mac_address`  | string | MAC address of the cable modem    |
| `ip_address`   | string | IP address of the cable modem     |
| `snmp`         | object | SNMPv2c or SNMPv3 configuration   |
| `snmp.snmpV2C` | object | SNMPv2c options (`community`)     |
| `snmp.snmpV3`  | object | SNMPv3 options (auth & priv keys) |

```json
{
  "cable_modem": {
	"mac_address": "aa:bb:cc:dd:ee:ff",
	"ip_address": "192.168.0.100",
  "snmp": {
    "snmpV2C": {
      "community": "private"
    },
    "snmpV3": {
      "username": "string",
      "securityLevel": "noAuthNoPriv",
      "authProtocol": "MD5",
      "authPassword": "string",
      "privProtocol": "DES",
      "privPassword": "string"
    }
  }
}
```


## Response Body (JSON)

```json
[
  {
    "index": <SNMP_INDEX>,
    "channel_id": <CHANNEL_ID>,
    "entry": {
      "docsIf31CmUsOfdmaChanChannelId": 42,
      "docsIf31CmUsOfdmaChanConfigChangeCt": 1,
      "docsIf31CmUsOfdmaChanSubcarrierZeroFreq": 104800000,
      "docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum": 74,
      "docsIf31CmUsOfdmaChanLastActiveSubcarrierNum": 1969,
      "docsIf31CmUsOfdmaChanNumActiveSubcarriers": 1896,
      "docsIf31CmUsOfdmaChanSubcarrierSpacing": 50,
      "docsIf31CmUsOfdmaChanCyclicPrefix": 192,
      "docsIf31CmUsOfdmaChanRollOffPeriod": 128,
      "docsIf31CmUsOfdmaChanNumSymbolsPerFrame": 10,
      "docsIf31CmUsOfdmaChanTxPower": 17.1,
      "docsIf31CmUsOfdmaChanPreEqEnabled": true,
      "docsIf31CmStatusOfdmaUsT3Timeouts": 0,
      "docsIf31CmStatusOfdmaUsT4Timeouts": 0,
      "docsIf31CmStatusOfdmaUsRangingAborteds": 0,
      "docsIf31CmStatusOfdmaUsT3Exceededs": 0,
      "docsIf31CmStatusOfdmaUsIsMuted": false,
      "docsIf31CmStatusOfdmaUsRangingStatus": "success"
    }
  }
]
```


## Response Field Highlights

| Field                                           | Type  | Description                                     |
| ----------------------------------------------- | ----- | ----------------------------------------------- |
| `docsIf31CmUsOfdmaChanChannelId`                | int   | Upstream channel ID                             |
| `docsIf31CmUsOfdmaChanConfigChangeCt`           | int   | Count of configuration changes since modem boot |
| `docsIf31CmUsOfdmaChanSubcarrierZeroFreq`       | int   | Frequency of subcarrier index 0 (Hz)            |
| `docsIf31CmUsOfdmaChanFirstActiveSubcarrierNum` | int   | First active subcarrier index                   |
| `docsIf31CmUsOfdmaChanLastActiveSubcarrierNum`  | int   | Last active subcarrier index                    |
| `docsIf31CmUsOfdmaChanNumActiveSubcarriers`     | int   | Total active subcarriers                        |
| `docsIf31CmUsOfdmaChanSubcarrierSpacing`        | int   | Subcarrier spacing in Hz                        |
| `docsIf31CmUsOfdmaChanCyclicPrefix`             | int   | Cyclic prefix duration                          |
| `docsIf31CmUsOfdmaChanRollOffPeriod`            | int   | Roll-off period                                 |
| `docsIf31CmUsOfdmaChanNumSymbolsPerFrame`       | int   | Number of OFDMA symbols per frame               |
| `docsIf31CmUsOfdmaChanTxPower`                  | float | Transmit power in dBm                           |
| `docsIf31CmUsOfdmaChanPreEqEnabled`             | bool  | Whether pre-equalization is enabled             |
| `docsIf31CmStatusOfdmaUsT3Timeouts`             | int   | T3 timeout count                                |
| `docsIf31CmStatusOfdmaUsT4Timeouts`             | int   | T4 timeout count                                |
| `docsIf31CmStatusOfdmaUsRangingAborteds`        | int   | Number of aborted ranging attempts              |
| `docsIf31CmStatusOfdmaUsT3Exceededs`            | int   | Number of times T3 retries exceeded             |
| `docsIf31CmStatusOfdmaUsIsMuted`                | bool  | Indicates if the upstream is muted              |
| `docsIf31CmStatusOfdmaUsRangingStatus`          | string | Ranging state name (e.g., `success`).           |


## Notes

* Use this endpoint to monitor upstream channel state, power, and timeouts.
* Useful for diagnosing access failures, ranging issues, or transmit mismatches.
* Each response object corresponds to a separate upstream OFDMA channel.

# FILE: tests/test_docs_if31_cm_status_ofdma_us_ranging_status.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIf31CmUsOfdmaChanEntry import DocsIf31CmUsOfdmaChanEntry
from pypnm.lib.constants import DocsIf31CmStatusOfdmaUsRangingStatus
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    async def get(self, oid: str) -> tuple[str, str]:
        return (oid, self._values.get(oid, ""))


@pytest.mark.asyncio
async def test_docs_if31_cm_status_ofdma_us_ranging_status_maps_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "docsIf31CmStatusOfdmaUsRangingStatus.1": "4",
        "docsIf31CmUsOfdmaChanChannelId.1": "1",
    }

    fake = _FakeSnmp(values)
    monkeypatch.setattr(Snmp_v2c, "get_result_value", lambda res: res[1])

    result = await DocsIf31CmUsOfdmaChanEntry.from_snmp(1, fake)
    assert result.entry.docsIf31CmStatusOfdmaUsRangingStatus == (
        DocsIf31CmStatusOfdmaUsRangingStatus.SUCCESS
    )
