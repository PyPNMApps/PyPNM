
from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia
from pydantic import BaseModel

from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class SystemConfigModel(BaseModel):
    FastApiRequestDefault: dict[str, object]
    SNMP: dict[str, object]
    PnmBulkDataTransfer: dict[str, object]
    PnmFileRetrieval: dict[str, object]
    PnmArtifactStorage: PnmArtifactStorageConfig
    logging: dict[str, object]
