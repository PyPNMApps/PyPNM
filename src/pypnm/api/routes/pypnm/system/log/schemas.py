
from __future__ import annotations

from typing import Any

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from pydantic import BaseModel


class SystemConfigModel(BaseModel):
    FastApiRequestDefault: dict[str, Any]
    SNMP: dict[str, Any]
    PnmBulkDataTransfer: dict[str, Any]
    PnmFileRetrieval: dict[str, Any]
    logging: dict[str, Any]
