from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import IntEnum


class FileType(IntEnum):
    """
    Enumeration of supported file output types:

    - JSON: JavaScript Object Notation format (media type "application/json")
    - CSV: Comma-Separated Values format (media type "text/csv")
    - PNG: Portable Network Graphics image format (media type "image/png")
    - XLSX: Microsoft Excel Open XML Spreadsheet format (media type "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    - ARCHIVE: Aggregate archive format (e.g., ZIP) that may contain multiple file types
               such as CSV, PNG, and other artifacts
               (media type "application/zip")
    """

    JSON = 0
    CSV = 1
    PNG = 2
    XLSX = 3
    ARCHIVE = 4
