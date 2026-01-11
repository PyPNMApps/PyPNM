# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging

from pypnm.pnm.parser.model.pnm_base_model import PnmBaseModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader


class CmLatencyModel(PnmBaseModel):
    """Pydantic model for Latency Report data -> PnmBaseModel"""

    pass


class CmLatencyRpt(PnmHeader):
    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._process()

    def _process(self) -> None:
        """
        Number of LatencySummaryData objects (n)    1 byte
        Latency Data                                n*LatencySummaryData
        """
        file_type = self.get_pnm_file_type()
        if file_type != PnmFileType.LATENCY_REPORT:
            cann = PnmFileType.LATENCY_REPORT.get_pnm_cann()
            actual_cann = file_type.get_pnm_cann() if file_type else "Unknown"
            raise ValueError(
                f"PNM File Stream is not RxMER file type: {cann}, Error: {actual_cann}"
            )

        return None

    def to_model(self) -> CmLatencyModel:
        """Convert parsed data to a Pydantic model"""
        return CmLatencyModel()
