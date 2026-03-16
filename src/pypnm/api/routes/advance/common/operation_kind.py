# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia
from __future__ import annotations

from pydantic import BaseModel, Field

from pypnm.lib.types import StringEnum


class MultiCaptureOperation(StringEnum):
    """Canonical operation families for persisted multi-capture records."""

    MULTI_RXMER = "multi_rxmer"
    MULTI_DS_CHANNEL_ESTIMATION = "multi_ds_channel_estimation"
    MULTI_US_OFDMA_PRE_EQUALIZATION = "multi_us_ofdma_pre_equalization"


class MultiCaptureOperationModel(BaseModel):
    """Persisted operation identity for replaying a completed multi-capture."""

    name: MultiCaptureOperation = Field(..., description="Canonical multi-capture operation family name.")
    measure_mode: str = Field(..., description="Normalized measure mode name used when the operation was started.")
