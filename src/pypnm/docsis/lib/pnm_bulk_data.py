from __future__ import annotations

import ipaddress

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from dataclasses import dataclass


@dataclass
class DocsPnmBulkDataGroup:
    docsPnmBulkDestIpAddrType: int | None  # e.g., 1 for IPv4, 2 for IPv6
    docsPnmBulkDestIpAddr: str | None  # string form of IP address
    docsPnmBulkDestPath: str | None  # path as a string (URL or file path)
    docsPnmBulkUploadControl: int | None  # control flag or enum

    docsPnmBulkFileName: str | None  # name of the file
    docsPnmBulkFileControl: int | None  # control flag or enum
    docsPnmBulkFileUploadStatus: int | None  # status flag or enum

    def __post_init__(self) -> None:
        if self.docsPnmBulkDestIpAddr:
            try:
                ipaddress.ip_address(self.docsPnmBulkDestIpAddr)
            except ValueError:
                raise ValueError(
                    f"Invalid IP address: {self.docsPnmBulkDestIpAddr}"
                ) from None


@dataclass
class DocsPnmBulkFileEntry:
    index: int
    docsPnmBulkFileName: str | None = None
    docsPnmBulkFileControl: int | None = None
    docsPnmBulkFileUploadStatus: int | None = None
