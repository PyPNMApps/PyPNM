# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.api.routes.common.classes.common_endpoint_classes.common_req_resp import (
    CommonSingleCaptureAnalysisType,
)
from pypnm.lib.types import FileName, MacAddressStr, TimeStamp, TransactionId


class FileQueryRequest(BaseModel):
    mac_address: MacAddressStr = Field(
        description="MAC address of the cable modem used when searching for registered PNM files"
    )


class FileEntry(BaseModel):
    transaction_id: TransactionId = Field(
        ..., description="Unique identifier for this file transaction"
    )
    filename: FileName = Field(..., description="Name of the file")
    pnm_test_type: str = Field(..., description="Type of PNM test performed")
    timestamp: TimeStamp = Field(..., description="Capture or transaction timestamp")
    system_description: dict | None = Field(
        None, description="Optional system description metadata"
    )


class FileQueryResponse(BaseModel):
    files: dict[str, list[FileEntry]] = Field(
        ..., description="Mapping of MAC address to list of PNM file entries"
    )


class UploadFileRequest(BaseModel):
    filename: FileName = Field(..., description="Name of the file to upload")
    data: str | None = Field(
        None, description="Optional base64-encoded or raw file data"
    )


class UploadFileResponse(BaseModel):
    mac_address: MacAddressStr = Field(
        description="MAC address associated with the uploaded file (placeholder null MAC until header inspection is wired in)",
    )
    filename: FileName = Field(..., description="Name of the file that was uploaded")
    transaction_id: TransactionId = Field(
        ..., description="Unique identifier for the created file transaction"
    )


class FileSearchRequest(BaseModel):
    transaction_id: TransactionId = Field(
        description="Transaction ID returned from file search"
    )


class FileAnalysisRequest(BaseModel):
    search: FileSearchRequest = Field(
        description="Transaction ID returned from file search"
    )
    analysis: CommonSingleCaptureAnalysisType = Field(
        description="Single capture analysis configuration"
    )


class AnalysisJsonResponse(BaseModel):
    mac_address: MacAddressStr = Field(
        description="MAC address associated with the analyzed file"
    )
    pnm_file_type: str = Field(..., description="PNM file type")
    status: str = Field(..., description="Status of the analysis operation")
    analysis: dict = Field(..., description="Analysis result in JSON format")


class HexDumpResponse(BaseModel):
    transaction_id: TransactionId = Field(
        ..., description="Transaction ID associated with the PNM file."
    )
    bytes_per_line: int = Field(
        ..., description="Number of bytes rendered per hexdump output line."
    )
    lines: list[str] = Field(
        default_factory=list,
        description="Hexdump lines with offset, hex bytes, and ASCII text.",
    )


class MacAddressSystemDescriptorEntry(BaseModel):
    mac_address: MacAddressStr = Field(..., description="Cable modem MAC address.")
    system_description: dict[str, str | int | float | bool] | None = Field(
        default=None, description="System descriptor (sysDescr fields) if available."
    )


class MacAddressSystemDescriptorResponse(BaseModel):
    mac_addresses: list[MacAddressSystemDescriptorEntry] = Field(
        ..., description="Unique MAC addresses that have registered PNM files."
    )
