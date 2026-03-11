# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from collections.abc import Sequence
from enum import Enum
from pathlib import Path
from typing import NewType, TypeAlias

import numpy as np
from numpy.typing import NDArray

# TODO: New home for these
GroupId             = NewType("GroupId", str)
TransactionId       = NewType("TransactionId", str)
TransactionRecord  = NewType("TransactionRecord", dict)
OperationId         = NewType("OperationId", str)

HashStr = NewType("HashStr", str)
ExitCode = NewType("ExitCode", int)

# Enum String Type
class StringEnum(str, Enum):
    """Py3.10-compatible StrEnum shim."""
    pass

class FloatEnum(float, Enum):
    """Float-like Enum base: members behave like floats."""
    pass

# Basic strings
String: TypeAlias       = str
StringArray: TypeAlias  = list[String]
JsonScalar: TypeAlias   = str | int | float | bool | None
JsonValue: TypeAlias    = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias   = dict[str, JsonValue]

# ────────────────────────────────────────────────────────────────────────────────
# Core numerics
# ────────────────────────────────────────────────────────────────────────────────
Number       = int | float | np.number
Float64      = np.float64
ByteArray    = list[np.uint8]

# Generic array-likes (inputs)
# TODO: Review to remove -> _ArrayLike = Union[Sequence[Number], NDArray[object]]
_ArrayLike   = Sequence[Number] | NDArray[np.generic]

ArrayLike    = list[Number]
ArrayLikeF64 = Sequence[float] | NDArray[np.float64]

# Canonical ndarray outputs (internal processing should normalize to these)
NDArrayF64: TypeAlias   = NDArray[np.float64]
NDArrayI64: TypeAlias   = NDArray[np.int64]
NDArrayC128: TypeAlias  = NDArray[np.complex128]
BoolArray: TypeAlias    = NDArray[np.bool_]

# ────────────────────────────────────────────────────────────────────────────────
# Simple series / containers  — use TypeAlias (recommended)
# ────────────────────────────────────────────────────────────────────────────────
IntSeries: TypeAlias        = list[int]
FloatSeries: TypeAlias      = list[float]
TwoDFloatSeries: TypeAlias  = list[FloatSeries]
FloatSequence: TypeAlias    = Sequence[float]

# Complex number encodings (JSON-safe)
Complex                  = tuple[float, float]  # (re, im)
ComplexArray: TypeAlias  = list[Complex]        # K × (re, im)
ComplexSeries: TypeAlias = list[complex]        # Python complex list (internal use)
ComplexMatrix: TypeAlias = list[ComplexArray]

# ────────────────────────────────────────────────────────────────────────────────
# Modulation profile identifiers
# ────────────────────────────────────────────────────────────────────────────────
ProfileId = NewType("ProfileId", int)

# ────────────────────────────────────────────────────────────────────────────────
# Paths / filesystem
# ────────────────────────────────────────────────────────────────────────────────
PathLike    = str | Path
PathArray   = list[PathLike]
FileNameStr = NewType("FileNameStr", str)

# ────────────────────────────────────────────────────────────────────────────────
# JSON-like structures for REST I/O
# ────────────────────────────────────────────────────────────────────────────────
JSONScalar = str | int | float | bool | None
JSONDict   = dict[str, "JSONValue"]
JSONList   = list["JSONValue"]
JSONValue  = JSONScalar | JSONDict | JSONList

# ────────────────────────────────────────────────────────────────────────────────
# Unit-tagged NewTypes (scalars only; runtime = underlying type)
# ────────────────────────────────────────────────────────────────────────────────
# Time / index
CaptureTime   = NewType("CaptureTime", int)
TimeStamp     = NewType("TimeStamp", int)
TimestampSec  = NewType("TimestampSec", int)
TimestampMs   = NewType("TimestampMs", int)
TimeStampUs   = NewType("TimeStampUs", int)
TimeStampNs   = NewType("TimeStampNs", int)
SampleIndex   = NewType("SampleIndex", int)

# RF / PHY units (keep as scalars with units)
FrequencyHz   = NewType("FrequencyHz", int)
BandwidthHz   = NewType("BandwidthHz", int)
ResolutionBw  = NewType("ResolutionBw", int)
SegmentFreqSpan = NewType("SegmentFreqSpan", int)
NumBins       = NewType("NumBins", int)

PowerdBmV     = NewType("PowerdBmV", float)
PowerdB       = NewType("PowerdB", float)
MERdB         = NewType("MERdB", float)
SNRdB         = NewType("SNRdB", float)
SNRln         = NewType("SNRln", float)

# DOCSIS identifiers
ChannelId     = NewType("ChannelId", int)
SubcarrierId  = NewType("SubcarrierId", int)
SubcarrierIdx = NewType("SubcarrierIdx", int)
PortId        = NewType("PortId", int)

# SNMP identifiers
OidStr          = NewType("OidStr", str)              # symbolic or dotted-decimal
OidNumTuple     = NewType("OidNumTuple", tuple[int, ...])
SnmpIndex       = NewType("SnmpIndex", int)
InterfaceIndex  = NewType("InterfaceIndex", int)
InterfaceIndexStr = NewType("InterfaceIndexStr", str)
EntryIndex      = NewType("EntryIndex", int)

# Network addressing (store as plain strings; validate elsewhere)
HostNameStr     = NewType("HostNameStr", str)
SnmpReadCommunity  = NewType("SnmpReadCommunity", str)
SnmpWriteCommunity = NewType("SnmpWriteCommunity", str)
SnmpCommunity      = SnmpReadCommunity
MacAddressStr   = NewType("MacAddressStr", str)         # aa:bb:cc:dd:ee:ff | aa-bb-cc-dd-ee-ff | aabb.ccdd.eeff | aabbccddeeff | aabbcc:ddeeff |
BridgeAddressStr = NewType("BridgeAddressStr", MacAddressStr)
InetAddressStr  = NewType("InetAddressStr", str)        # 192.168.0.1 | 2001:db8::1
IPv4Str         = NewType("IPv4Str", InetAddressStr)    # 192.168.0.1
IPv6Str         = NewType("IPv6Str", InetAddressStr)    # 2001:db8::1

# File tokens
FileStem      = NewType("FileStem", str)            # name without extension
FileExt       = NewType("FileExt", str)             # ".csv", ".png", …
FileName      = NewType("FileName", str)

# ────────────────────────────────────────────────────────────────────────────────
# Analysis-specific tuples / series
# ────────────────────────────────────────────────────────────────────────────────
RegressionCoeffs = tuple[float, float]              # (slope, intercept)
RegressionStats  = tuple[float, float, float]       # (slope, intercept, r2)

# Spectrum analysis extension payloads
SpectrumAnalysisSnmpCaptureParameters: TypeAlias = dict[str, int | float]
ResolutionBwSettings: TypeAlias = tuple[ResolutionBw, NumBins, SegmentFreqSpan]

# RxMER / spectrum containers
FrequencySeriesHz: TypeAlias = list[FrequencyHz]
MerSeriesdB: TypeAlias       = FloatSeries
ShannonSeriesdB: TypeAlias   = FloatSeries
MagnitudeSeries: TypeAlias   = FloatSeries

BitsPerSymbol       = NewType("BitsPerSymbol", int)
BitsPerSymbolSeries: TypeAlias = list[BitsPerSymbol]

Microseconds = NewType("Microseconds", float)

# IFFT time response
IfftTimeResponse: TypeAlias = tuple[NDArrayF64, NDArrayC128]

# ────────────────────────────────────────────────────────────────────────────────
# HTTP return code type
# ────────────────────────────────────────────────────────────────────────────────
HttpRtnCode = NewType("HttpRtnCode", int)

ScalarValue: TypeAlias = float | int | str

# ────────────────────────────────────────────────────────────────────────────────
# SSH return code type
# ────────────────────────────────────────────────────────────────────────────────
UserNameStr         = NewType("UserNameStr", str)

SshOk: TypeAlias    = bool
SshStdout           = NewType("SshStdout", str)
SshStderr           = NewType("SshStderr", str)
SshExitCode         = NewType("SshExitCode", int)
SshCommandResult: TypeAlias = tuple[SshStdout, SshStderr, SshExitCode]

RemoteDirEntry             = NewType("RemoteDirEntry", str)
RemoteDirEntries: TypeAlias = list[RemoteDirEntry]

STATUS:TypeAlias = bool

RealInt = NewType("RealInt", int)
ImginaryInt  = NewType("ImginaryInt", int)
PreEqAtdmaCoefficients = tuple[RealInt,ImginaryInt]

# ────────────────────────────────────────────────────────────────────────────────
# Explicit public surface
# ────────────────────────────────────────────────────────────────────────────────
__all__ = [
    "STATUS",
    "SshOk", "SshStdout", "SshStderr", "SshExitCode", "SshCommandResult",
    "RemoteDirEntry", "RemoteDirEntries", "UserNameStr",
    "ScalarValue",
    "HashStr",
    "TransactionId", "GroupId", "OperationId",
    # enums
    "StringEnum", "FloatEnum",
    # strings
    "String", "StringArray",
    "ByteArray",
    # numerics
    "Number", "Float64", "ArrayLike", "ArrayLikeF64", "NDArrayF64", "NDArrayI64", "BoolArray",
    "FloatSeries", "TwoDFloatSeries", "FloatSequence", "IntSeries",
    # complex
    "Complex", "ComplexArray", "ComplexSeries",
    # paths
    "PathLike", "PathArray", "FileNameStr",
    # JSON
    "JSONScalar", "JSONDict", "JSONList", "JSONValue",
    # unit-tagged scalars
    "CaptureTime", "TimeStamp", "TimestampSec", "TimestampMs", "TimeStampUs", "TimeStampNs",
    "SampleIndex",
    "FrequencyHz", "BandwidthHz", "ResolutionBw", "SegmentFreqSpan", "NumBins",
    "PowerdBmV", "PowerdB", "MERdB", "SNRdB", "SNRln",
    "ChannelId", "SubcarrierId", "PortId",
    "OidStr", "OidNumTuple",
    "SnmpReadCommunity", "SnmpWriteCommunity", "SnmpCommunity",
    "MacAddressStr", "BridgeAddressStr", "IPv4Str", "IPv6Str",
    "FileStem", "FileExt", "FileName",
    # analysis tuples / series
    "RegressionCoeffs", "RegressionStats", "SpectrumAnalysisSnmpCaptureParameters", "ResolutionBwSettings",
    "FrequencySeriesHz", "MerSeriesdB", "ShannonSeriesdB", "MagnitudeSeries",
    # modulation/profile & misc
    "ProfileId", "BitsPerSymbol", "BitsPerSymbolSeries", "Microseconds",
    "HttpRtnCode", "InterfaceIndex", "InterfaceIndexStr", "EntryIndex"
]
