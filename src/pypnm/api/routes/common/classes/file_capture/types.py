# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from pypnm.docsis.cm_snmp_operation import SystemDescriptor
from pypnm.docsis.data_type.sysDescr import SystemDescriptorModel
from pypnm.lib.mac_address import MacAddress
from pypnm.lib.types import FileName, MacAddressStr, TimestampSec, TransactionId

Record              = dict[str, Any]
TransactionRecord   = dict[TransactionId, Record]

class DeviceDetailsModel(BaseModel):
    system_description: SystemDescriptorModel = Field(..., description="Parsed system descriptor")

class CompressionMetadataModel(BaseModel):
    is_compressed: bool = Field(..., description="Whether the artifact is stored in compressed form.")
    codec: str = Field(..., description="Compression codec name (zstd, gzip, or none).")
    level: int = Field(..., description="Compression level used for storage.")
    size_before: int = Field(..., description="Original artifact size in bytes before compression.")
    size_after: int = Field(..., description="Compressed artifact size in bytes.")

class TransactionRecordModel(BaseModel):
    transaction_id: TransactionId       = Field(..., description="16-char transaction ID")
    timestamp: TimestampSec             = Field(..., description="Epoch seconds")
    mac_address: MacAddressStr          = Field(..., description="Cable modem MAC address")
    pnm_test_type: str                  = Field(..., description="PNM test type")
    filename: FileName                  = Field(..., description="Capture filename")
    device_details: DeviceDetailsModel  = Field(..., description="Device details container")
    compression: CompressionMetadataModel | None = Field(default=None, description="Compression metadata for stored artifacts.")

    @classmethod
    def null(cls) -> TransactionRecordModel:
        return cls(
            transaction_id  =   TransactionId(""),
            timestamp       =   TimestampSec(0),
            mac_address     =   MacAddressStr(MacAddress.null()),
            pnm_test_type   =   "",
            filename        =   FileName(""),
            device_details=DeviceDetailsModel(system_description=SystemDescriptor.empty().to_model()),
            compression     =   None,
        )
