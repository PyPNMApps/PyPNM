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
