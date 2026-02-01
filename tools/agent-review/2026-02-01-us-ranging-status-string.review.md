## Agent Review Bundle Summary
- Goal: Convert docsIf3CmStatusUsRangingStatus to string values via a shared enum.
- Changes: Added DocsIf3CmStatusUsRangingStatus enum, normalized ranging status output to strings, updated docs, and added tests.
- Files: src/pypnm/lib/constants.py, src/pypnm/docsis/data_type/DocsIfUpstreamChannelEntry.py, docs/api/fast-api/single/us/atdma/chan/stats.md, tests/test_docs_if3_cm_status_us_ranging_status.py
- Tests: ruff check src; pytest -q
- Notes: Used ruff import fix for DocsIfUpstreamChannelEntry.py to satisfy import sorting; hardware SNMP integration tests skipped (PNM_CM_IT not set).

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
    "DEFAULT_SPECTRUM_ANALYZER_INDICES",
    "FEC_SUMMARY_TYPE_STEP_SECONDS", "FEC_SUMMARY_TYPE_LABEL",
]

# FILE: src/pypnm/docsis/data_type/DocsIfUpstreamChannelEntry.py

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import logging
from collections.abc import Callable

from pydantic import BaseModel

from pypnm.lib.constants import DocsIf3CmStatusUsRangingStatus
from pypnm.snmp.snmp_v2c import Snmp_v2c


class DocsIfUpstreamEntry(BaseModel):
    docsIfUpChannelId: int | None = None
    docsIfUpChannelFrequency: int | None = None
    docsIfUpChannelWidth: int | None = None
    docsIfUpChannelModulationProfile: int | None = None
    docsIfUpChannelSlotSize: int | None = None
    docsIfUpChannelTxTimingOffset: int | None = None
    docsIfUpChannelRangingBackoffStart: int | None = None
    docsIfUpChannelRangingBackoffEnd: int | None = None
    docsIfUpChannelTxBackoffStart: int | None = None
    docsIfUpChannelTxBackoffEnd: int | None = None
    docsIfUpChannelType: int | None = None
    docsIfUpChannelCloneFrom: int | None = None
    docsIfUpChannelUpdate: bool | None = None
    docsIfUpChannelStatus: int | None = None
    docsIfUpChannelPreEqEnable: bool | None = None

    # DOCS-IF3-MIB extensions
    docsIf3CmStatusUsTxPower: float | None = None
    docsIf3CmStatusUsT3Timeouts: int | None = None
    docsIf3CmStatusUsT4Timeouts: int | None = None
    docsIf3CmStatusUsRangingAborteds: int | None = None
    docsIf3CmStatusUsModulationType: int | None = None
    docsIf3CmStatusUsEqData: str | None = None
    docsIf3CmStatusUsT3Exceededs: int | None = None
    docsIf3CmStatusUsIsMuted: bool | None = None
    docsIf3CmStatusUsRangingStatus: DocsIf3CmStatusUsRangingStatus | None = None

class DocsIfUpstreamChannelEntry(BaseModel):
    index: int
    channel_id: int
    entry: DocsIfUpstreamEntry

    @classmethod
    async def from_snmp(cls, index: int, snmp: Snmp_v2c) -> DocsIfUpstreamChannelEntry | None:
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

        entry = DocsIfUpstreamEntry(
            docsIfUpChannelId                   =   await fetch("docsIfUpChannelId", int),
            docsIfUpChannelFrequency            =   await fetch("docsIfUpChannelFrequency", int),
            docsIfUpChannelWidth                =   await fetch("docsIfUpChannelWidth", int),
            docsIfUpChannelModulationProfile    =   await fetch("docsIfUpChannelModulationProfile", int),
            docsIfUpChannelSlotSize             =   await fetch("docsIfUpChannelSlotSize", int),
            docsIfUpChannelTxTimingOffset       =   await fetch("docsIfUpChannelTxTimingOffset", int),
            docsIfUpChannelRangingBackoffStart =   await fetch("docsIfUpChannelRangingBackoffStart", int),
            docsIfUpChannelRangingBackoffEnd   =   await fetch("docsIfUpChannelRangingBackoffEnd", int),
            docsIfUpChannelTxBackoffStart      =   await fetch("docsIfUpChannelTxBackoffStart", int),
            docsIfUpChannelTxBackoffEnd        =   await fetch("docsIfUpChannelTxBackoffEnd", int),
            docsIfUpChannelType                =   await fetch("docsIfUpChannelType", int),
            docsIfUpChannelCloneFrom           =   await fetch("docsIfUpChannelCloneFrom", int),
            docsIfUpChannelUpdate              =   await fetch("docsIfUpChannelUpdate", Snmp_v2c.truth_value),
            docsIfUpChannelStatus              =   await fetch("docsIfUpChannelStatus", int),
            docsIfUpChannelPreEqEnable         =   await fetch("docsIfUpChannelPreEqEnable", Snmp_v2c.truth_value),

            docsIf3CmStatusUsTxPower           =   await fetch("docsIf3CmStatusUsTxPower", tenthdBmV_to_float),
            docsIf3CmStatusUsT3Timeouts        =   await fetch("docsIf3CmStatusUsT3Timeouts", int),
            docsIf3CmStatusUsT4Timeouts        =   await fetch("docsIf3CmStatusUsT4Timeouts", int),
            docsIf3CmStatusUsRangingAborteds   =   await fetch("docsIf3CmStatusUsRangingAborteds", int),
            docsIf3CmStatusUsModulationType    =   await fetch("docsIf3CmStatusUsModulationType", int),
            docsIf3CmStatusUsEqData            =   await fetch("docsIf3CmStatusUsEqData", str),
            docsIf3CmStatusUsT3Exceededs       =   await fetch("docsIf3CmStatusUsT3Exceededs", int),
            docsIf3CmStatusUsIsMuted           =   await fetch("docsIf3CmStatusUsIsMuted", Snmp_v2c.truth_value),
            docsIf3CmStatusUsRangingStatus     =   DocsIf3CmStatusUsRangingStatus.from_int(
                await fetch("docsIf3CmStatusUsRangingStatus", int),
            )
        )

        return cls(
            index=index,
            channel_id=entry.docsIfUpChannelId or 0,
            entry=entry
        )

    @classmethod
    async def get(cls, snmp: Snmp_v2c, indices: list[int]) -> list[DocsIfUpstreamChannelEntry]:
        logger = logging.getLogger(cls.__name__)
        results: list[DocsIfUpstreamChannelEntry] = []

        if not indices:
            logger.warning("No upstream ATDMA indices found.")
            return results

        for index in indices:
            result = await cls.from_snmp(index, snmp)
            if result is not None:
                results.append(result)

        return results

# FILE: docs/api/fast-api/single/us/atdma/chan/stats.md
# DOCSIS 3.0 Upstream ATDMA Channel Statistics

Provides Access To DOCSIS 3.0 Upstream SC-QAM (ATDMA) Channel Statistics.

## Endpoint

**POST** `/docs/if30/us/atdma/chan/stats`

## Request

Use the SNMP-only format: [Common → Request](../../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../../common/response.md) (`mac_address`, `status`, `message`, `data`).

`data` is an **object** with the upstream channel entries plus an optional DWR window evaluation summary. Each entry contains the SNMP table `index`, the upstream `channel_id`, and an `entry` with configuration, status, and (where available) raw pre-EQ data (`docsIf3CmStatusUsEqData`).

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "entries": [
      {
        "index": 80,
        "channel_id": 1,
        "entry": {
          "docsIfUpChannelId": 1,
          "docsIfUpChannelFrequency": 14600000,
          "docsIfUpChannelWidth": 6400000,
          "docsIfUpChannelModulationProfile": 0,
          "docsIfUpChannelSlotSize": 2,
          "docsIfUpChannelTxTimingOffset": 6436,
          "docsIfUpChannelRangingBackoffStart": 3,
          "docsIfUpChannelRangingBackoffEnd": 8,
          "docsIfUpChannelTxBackoffStart": 2,
          "docsIfUpChannelTxBackoffEnd": 6,
          "docsIfUpChannelType": 2,
          "docsIfUpChannelCloneFrom": 0,
          "docsIfUpChannelUpdate": false,
          "docsIfUpChannelStatus": 1,
          "docsIfUpChannelPreEqEnable": true,
          "docsIf3CmStatusUsTxPower": 49.0,
          "docsIf3CmStatusUsT3Timeouts": 0,
          "docsIf3CmStatusUsT4Timeouts": 0,
          "docsIf3CmStatusUsRangingAborteds": 0,
          "docsIf3CmStatusUsModulationType": 2,
          "docsIf3CmStatusUsEqData": "0x08011800ffff0003...00020001",
          "docsIf3CmStatusUsT3Exceededs": 0,
          "docsIf3CmStatusUsIsMuted": false,
          "docsIf3CmStatusUsRangingStatus": "success"
        }
      },
      {
        "index": 81,
        "channel_id": 2,
        "entry": {
          "docsIfUpChannelId": 2,
          "docsIfUpChannelFrequency": 21000000,
          "docsIfUpChannelWidth": 6400000,
          "docsIfUpChannelModulationProfile": 0,
          "docsIfUpChannelSlotSize": 2,
          "docsIfUpChannelTxTimingOffset": 6436,
          "docsIfUpChannelRangingBackoffStart": 3,
          "docsIfUpChannelRangingBackoffEnd": 8,
          "docsIfUpChannelTxBackoffStart": 2,
          "docsIfUpChannelTxBackoffEnd": 6,
          "docsIfUpChannelType": 2,
          "docsIfUpChannelCloneFrom": 0,
          "docsIfUpChannelUpdate": false,
          "docsIfUpChannelStatus": 1,
          "docsIfUpChannelPreEqEnable": true,
          "docsIf3CmStatusUsTxPower": 48.5,
          "docsIf3CmStatusUsT3Timeouts": 0,
          "docsIf3CmStatusUsT4Timeouts": 0,
          "docsIf3CmStatusUsRangingAborteds": 0,
          "docsIf3CmStatusUsModulationType": 2,
          "docsIf3CmStatusUsEqData": "0x08011800ffff0001...0002",
          "docsIf3CmStatusUsT3Exceededs": 0,
          "docsIf3CmStatusUsIsMuted": false,
          "docsIf3CmStatusUsRangingStatus": "success"
        }
      }
    ],
    "dwr_window_check": {
      "dwr_warning_db": 6.0,
      "dwr_violation_db": 12.0,
      "channel_count": 2,
      "min_power_dbmv": 48.5,
      "max_power_dbmv": 49.0,
      "spread_db": 0.5,
      "is_warning": false,
      "is_violation": false,
      "extreme_channel_ids": [1, 2]
    }
  }
}
```

## Data Fields

| Field              | Type   | Description                                      |
| ------------------ | ------ | ------------------------------------------------ |
| `entries`          | array  | Upstream channel entries (same as prior format). |
| `dwr_window_check` | object | DWR evaluation summary, or null when unavailable. |

## DWR Window Check Fields

| Field              | Type  | Units | Description |
| ------------------ | ----- | ----- | ----------- |
| `dwr_warning_db`   | float | dB    | Warning threshold for the DWR spread. |
| `dwr_violation_db` | float | dB    | Violation threshold for the DWR spread. |
| `channel_count`    | int   | —     | Number of channels included in the evaluation. |
| `min_power_dbmv`   | float | dBmV  | Minimum transmit power across channels. |
| `max_power_dbmv`   | float | dBmV  | Maximum transmit power across channels. |
| `spread_db`        | float | dB    | Power spread across channels (max-min). |
| `is_warning`       | bool  | —     | True when warning_db < spread_db <= violation_db. |
| `is_violation`     | bool  | —     | True when spread_db > violation_db. |
| `extreme_channel_ids` | array | —  | Channel IDs that define the min/max spread. |

## Channel Fields

| Field        | Type | Description                                                                 |
| ------------ | ---- | --------------------------------------------------------------------------- |
| `index`      | int  | **SNMP table index** (OID instance) for this channel’s row in the CM table. |
| `channel_id` | int  | DOCSIS upstream SC-QAM (ATDMA) logical channel ID.                          |

## Entry Fields

| Field                                | Type   | Units | Description                                             |
| ------------------------------------ | ------ | ----- | ------------------------------------------------------- |
| `docsIfUpChannelId`                  | int    | —     | Upstream channel ID (mirrors logical ID).               |
| `docsIfUpChannelFrequency`           | int    | Hz    | Center frequency.                                       |
| `docsIfUpChannelWidth`               | int    | Hz    | Channel width.                                          |
| `docsIfUpChannelModulationProfile`   | int    | —     | Modulation profile index.                               |
| `docsIfUpChannelSlotSize`            | int    | —     | Slot size (minislot units).                             |
| `docsIfUpChannelTxTimingOffset`      | int    | —     | Transmit timing offset (implementation-specific units). |
| `docsIfUpChannelRangingBackoffStart` | int    | —     | Initial ranging backoff window start.                   |
| `docsIfUpChannelRangingBackoffEnd`   | int    | —     | Initial ranging backoff window end.                     |
| `docsIfUpChannelTxBackoffStart`      | int    | —     | Data/backoff start window.                              |
| `docsIfUpChannelTxBackoffEnd`        | int    | —     | Data/backoff end window.                                |
| `docsIfUpChannelType`                | int    | —     | Channel type enum (e.g., `2` = ATDMA).                  |
| `docsIfUpChannelCloneFrom`           | int    | —     | Clone source channel (if used).                         |
| `docsIfUpChannelUpdate`              | bool   | —     | Indicates a pending/active update.                      |
| `docsIfUpChannelStatus`              | int    | —     | Operational status enum.                                |
| `docsIfUpChannelPreEqEnable`         | bool   | —     | Whether pre-equalization is enabled.                    |
| `docsIf3CmStatusUsTxPower`           | float  | dBmV  | Upstream transmit power.                                |
| `docsIf3CmStatusUsT3Timeouts`        | int    | —     | T3 timeouts counter.                                    |
| `docsIf3CmStatusUsT4Timeouts`        | int    | —     | T4 timeouts counter.                                    |
| `docsIf3CmStatusUsRangingAborteds`   | int    | —     | Aborted ranging attempts.                               |
| `docsIf3CmStatusUsModulationType`    | int    | —     | Modulation type enum.                                   |
| `docsIf3CmStatusUsEqData`            | string | hex   | Raw pre-EQ coefficient payload (hex string; raw octets). |
| `docsIf3CmStatusUsT3Exceededs`       | int    | —     | Exceeded T3 attempts.                                   |
| `docsIf3CmStatusUsIsMuted`           | bool   | —     | Whether the upstream transmitter is muted.              |
| `docsIf3CmStatusUsRangingStatus`     | string | —     | Ranging state name (e.g., `success`).                   |

## Notes

* `docsIf3CmStatusUsEqData` contains the raw equalizer payload; decode to taps (location, magnitude, phase) in analysis workflows.
* The hex string preserves original SNMP octets (for example `FF` stays `FF`, not UTF-8 encoded).
* Use the combination of `TxPower`, timeout counters, and ranging status to corroborate upstream health with pre-EQ shape.
* Channels are discovered automatically; no channel list is required in the request.
* DWR warning and violation thresholds are evaluated against the min/max power spread for all channels returned.
# DOCSIS 3.0 Upstream ATDMA Pre-Equalization

Provides Access To DOCSIS 3.0 Upstream SC-QAM (ATDMA) Pre-Equalization Tap Data For Plant Analysis (Reflections, Group Delay, Pre-Echo).

## Endpoint

**POST** `/docs/if30/us/scqam/chan/preEqualization`

## Request

Use the SNMP-only format: [Common → Request](../../../../common/request.md)  
TFTP parameters are not required.

## Response

This endpoint returns the standard envelope described in [Common → Response](../../../../common/response.md) (`mac_address`, `status`, `message`, `data`).

`data` is an **object** keyed by the **SNMP table index** of each upstream channel.  
Each value contains decoded tap configuration and coefficient arrays.

### Abbreviated Example

```json
{
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "status": 0,
  "message": null,
  "data": {
    "80": {
      "main_tap_location": 8,
      "forward_taps_per_symbol": 1,
      "num_forward_taps": 24,
      "num_reverse_taps": 0,
      "forward_coefficients": [
        { "real": 0, "imag": 4, "magnitude": 4.0, "magnitude_power_dB": 12.04 },
        { "real": 2, "imag": -15425, "magnitude": 15425.0, "magnitude_power_dB": 83.76 },
        { "real": -15426, "imag": 1, "magnitude": 15426.0, "magnitude_power_dB": 83.77 }
        /* ... taps elided ... */
      ],
      "reverse_coefficients": []
    },
    "81": {
      "main_tap_location": 8,
      "forward_taps_per_symbol": 1,
      "num_forward_taps": 24,
      "num_reverse_taps": 0,
      "forward_coefficients": [
        { "real": -15425, "imag": -15425, "magnitude": 21814.24, "magnitude_power_dB": 86.77 },
        { "real": 1, "imag": 3, "magnitude": 3.16, "magnitude_power_dB": 10.0 },
        { "real": 1, "imag": -15425, "magnitude": 15425.0, "magnitude_power_dB": 83.76 }
        /* ... taps elided ... */
      ],
      "reverse_coefficients": []
    }
    /* ... other upstream channel indices elided ... */
  }
}
```

## Container Keys

| Key (top-level under `data`) | Type   | Description                                                       |
| ---------------------------- | ------ | ----------------------------------------------------------------- |
| `"80"`, `"81"`, …            | string | **SNMP table index** for the upstream channel row (OID instance). |

## Channel-Level Fields

| Field                     | Type    | Description                                                 |
| ------------------------- | ------- | ----------------------------------------------------------- |
| `main_tap_location`       | integer | Location of the main tap (typically near the filter center) |
| `forward_taps_per_symbol` | integer | Number of forward taps per symbol                           |
| `num_forward_taps`        | integer | Total forward equalizer taps                                |
| `num_reverse_taps`        | integer | Total reverse equalizer taps (often `0` for ATDMA)          |
| `forward_coefficients`    | array   | Complex tap coefficients applied in forward direction       |
| `reverse_coefficients`    | array   | Complex tap coefficients applied in reverse direction       |
| `metrics`                 | object  | Derived equalizer metrics and frequency response            |

## Coefficient Object Fields

| Field                | Type  | Units | Description                          |
| -------------------- | ----- | ----- | ------------------------------------ |
| `real`               | int   | —     | Real part of the complex coefficient |
| `imag`               | int   | —     | Imaginary part of the coefficient    |
| `magnitude`          | float | —     | Magnitude of the complex tap         |
| `magnitude_power_dB` | float | dB    | Power of the tap in dB               |

## Equalizer Metrics Fields

| Field                           | Type  | Units | Description                                   |
| ------------------------------- | ----- | ----- | --------------------------------------------- |
| `main_tap_energy`               | float | —     | Main tap energy (MTE)                         |
| `main_tap_nominal_energy`       | float | —     | Main tap nominal energy (MTNE)                |
| `pre_main_tap_energy`           | float | —     | Pre-main tap energy (PreMTE)                  |
| `post_main_tap_energy`          | float | —     | Post-main tap energy (PostMTE)                |
| `total_tap_energy`              | float | —     | Total tap energy (TTE)                        |
| `main_tap_compression`          | float | dB    | Main tap compression (MTC)                    |
| `main_tap_ratio`                | float | dB    | Main tap ratio (MTR)                          |
| `non_main_tap_energy_ratio`     | float | dB    | Non-main tap to total energy ratio (NMTER)    |
| `pre_main_tap_total_energy_ratio` | float | dB  | Pre-main tap to total energy ratio (PreMTTER) |
| `post_main_tap_total_energy_ratio` | float | dB | Post-main tap to total energy ratio (PostMTTER) |
| `pre_post_energy_symmetry_ratio`  | float | dB | Pre-post energy symmetry ratio (PPESR)        |
| `pre_post_tap_symmetry_ratio`     | float | dB | Pre-post tap symmetry ratio (PPTSR)           |
| `frequency_response`              | object | —  | Frequency response derived from tap coefficients |

## Frequency Response Fields

| Field                         | Type          | Units | Description                                         |
| ----------------------------- | ------------- | ----- | --------------------------------------------------- |
| `fft_size`                    | integer       | —     | FFT size used to compute the response               |
| `frequency_bins`              | array[float]  | —     | Normalized bins from 0 to 1                         |
| `magnitude`                   | array[float]  | —     | Magnitude response per bin                          |
| `magnitude_power_db`          | array[float]  | dB    | Magnitude power per bin                             |
| `magnitude_power_db_normalized` | array[float] | dB    | Magnitude power normalized to the DC bin (bin 0)    |
| `phase_radians`               | array[float]  | rad   | Phase response per bin                              |

## Notes

* Each top-level key under `data` is the DOCSIS **SNMP index** for an upstream SC-QAM (ATDMA) channel.
* Forward taps pre-compensate the channel (handling pre-echo/echo paths); reverse taps are uncommon in ATDMA.
* Use tap shapes and main-tap offset to infer echo path delay and alignment health.
* Tap coefficients are signed integers; convert to floating-point as needed for analysis.
* `magnitude_power_db_normalized` references the DC bin (bin 0) as 0 dB when non-zero.

# FILE: tests/test_docs_if3_cm_status_us_ranging_status.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import pytest

from pypnm.docsis.data_type.DocsIfUpstreamChannelEntry import DocsIfUpstreamChannelEntry
from pypnm.lib.constants import DocsIf3CmStatusUsRangingStatus
from pypnm.snmp.snmp_v2c import Snmp_v2c


class _FakeSnmp:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    async def get(self, oid: str) -> tuple[str, str]:
        return (oid, self._values.get(oid, ""))


@pytest.mark.asyncio
async def test_docs_if3_cm_status_us_ranging_status_maps_success(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "docsIf3CmStatusUsRangingStatus.1": "4",
        "docsIfUpChannelId.1": "1",
    }

    fake = _FakeSnmp(values)
    monkeypatch.setattr(Snmp_v2c, "get_result_value", lambda res: res[1])

    result = await DocsIfUpstreamChannelEntry.from_snmp(1, fake)
    assert result.entry.docsIf3CmStatusUsRangingStatus == DocsIf3CmStatusUsRangingStatus.SUCCESS

