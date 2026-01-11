# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import Final, Literal, TypeAlias, TypeVar, cast

from pypnm.lib.types import (
    CaptureTime,
    ChannelId,
    FloatEnum,
    FrequencyHz,
    Number,
    ProfileId,
    StringEnum,
)

DEFAULT_SSH_PORT: int = 22

HZ: Final[int] = 1
KHZ: Final[int] = 1_000
MHZ: Final[int] = 1_000_000
GHZ: Final[int] = 1_000_000_000

FEET_PER_METER: Final[float] = 3.280839895013123
SPEED_OF_LIGHT: Final[float] = 299_792_458.0  # m/s

NULL_ARRAY_NUMBER: Final[list[Number]] = [0]

ZERO_FREQUENCY: Final[FrequencyHz] = cast(FrequencyHz, 0)

INVALID_CHANNEL_ID: Final[ChannelId] = cast(ChannelId, -1)
INVALID_PROFILE_ID: Final[ProfileId] = cast(ProfileId, -1)
INVALID_SUB_CARRIER_ZERO_FREQ: Final[FrequencyHz] = cast(FrequencyHz, 0)
INVALID_START_VALUE: Final[int] = -1
INVALID_SCHEMA_TYPE: Final[int] = -1
INVALID_CAPTURE_TIME: Final[CaptureTime] = cast(CaptureTime, -1)

DEFAULT_CAPTURE_TIME: Final[CaptureTime] = cast(CaptureTime, 19700101)  # epoch start

CableTypes: TypeAlias = Literal["RG6", "RG59", "RG11"]

# Velocity Factor (VF) by cable type (fraction of c0)
CABLE_VF: Final[dict[CableTypes, float]] = {
    "RG6": 0.87,
    "RG59": 0.82,
    "RG11": 0.87,
}


class CableType(FloatEnum):
    RG6 = 0.87
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

    APPLICATION_JSON = "application/json"
    APPLICATION_ZIP = "application/zip"
    APPLICATION_OCTET_STREAM = "application/octet-stream"
    TEXT_CSV = "text/csv"


class OperationExecutionState(StringEnum):
    """
    Canonical operation lifecycle state for async workflows.
    """

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


T = TypeVar("T")

DEFAULT_SPECTRUM_ANALYZER_INDICES: Final[list[int]] = [0]


FEC_SUMMARY_TYPE_STEP_SECONDS: dict[int, int] = {
    2: 1,  # interval10min(2): 600 samples, 1 sec apart
    3: 60,  # interval24hr(3): 1440 samples, 60 sec apart
    # other(1): unknown / device-specific, do not enforce
}

FEC_SUMMARY_TYPE_LABEL: dict[int, str] = {
    1: "other",
    2: "10-minute interval (1s cadence)",
    3: "24-hour interval (60s cadence)",
}

__all__ = [
    "DEFAULT_SSH_PORT",
    "HZ",
    "KHZ",
    "MHZ",
    "GHZ",
    "ZERO_FREQUENCY",
    "FEET_PER_METER",
    "SPEED_OF_LIGHT",
    "NULL_ARRAY_NUMBER",
    "INVALID_CHANNEL_ID",
    "INVALID_PROFILE_ID",
    "INVALID_SUB_CARRIER_ZERO_FREQ",
    "INVALID_START_VALUE",
    "INVALID_SCHEMA_TYPE",
    "INVALID_CAPTURE_TIME",
    "DEFAULT_CAPTURE_TIME",
    "CableTypes",
    "CABLE_VF",
    "DEFAULT_SPECTRUM_ANALYZER_INDICES",
    "FEC_SUMMARY_TYPE_STEP_SECONDS",
    "FEC_SUMMARY_TYPE_LABEL",
    "OperationExecutionState",
]
