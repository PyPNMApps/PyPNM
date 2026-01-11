# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from struct import calcsize, unpack

from pypnm.pnm.lib.fixed_point_decoder import (
    ComplexSeries,
    FixedPointDecoder,
    FractionalBits,
    IntegerBits,
)
from pypnm.pnm.parser.model.pnm_base_model import PnmBaseModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader


class CmSymbolCaptureModel(PnmBaseModel):
    """Pydantic model for Symbol Capture Report data"""

    pass


class CmSymbolCapture(PnmHeader):
    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)

        # Additional attributes specific to CmSymbolCapture
        self.channel_id: int | None = None
        self.mac_address: str | None = None
        self.subcarrier_zero_frequency: int | None = None
        self.sample_rate: int | None = None
        self.fft_size: int | None = None
        self.trigger_group_id: int | None = None
        self.transaction_id: int | None = None
        self.capture_data_length: int | None = None
        self.capture_data: bytes | None = None

    def process_cm_symbol_capture(self) -> None:
        if self.get_pnm_file_type() != PnmFileType.SYMBOL_CAPTURE:
            cann = PnmFileType.SYMBOL_CAPTURE.get_pnm_cann()
            actual_type = self.get_pnm_file_type()
            error_cann = actual_type.get_pnm_cann() if actual_type else "Unknown"
            raise ValueError(
                f"PNM File Stream is not RxMER file type: {cann}, Error: {error_cann}"
            )

        # Extract CmSymbolCapture fields using struct.unpack
        cm_symbol_capture_format = "<B6sII2HI"
        cm_symbol_capture_size = unpack(
            cm_symbol_capture_format,
            self.pnm_data[: calcsize(cm_symbol_capture_format)],
        )

        # Assign values to attributes
        self.channel_id = cm_symbol_capture_size[0]
        self.mac_address = cm_symbol_capture_size[1].hex(":")
        self.subcarrier_zero_frequency = cm_symbol_capture_size[2]
        self.sample_rate = cm_symbol_capture_size[3]
        self.fft_size = cm_symbol_capture_size[4]
        self.trigger_group_id = cm_symbol_capture_size[5]
        self.transaction_id = cm_symbol_capture_size[6]
        self.capture_data_length = cm_symbol_capture_size[7]
        self.capture_data = self.pnm_data[calcsize(cm_symbol_capture_format) :]

    def process_capture_data(
        self,
        sm_n_format: tuple[IntegerBits, FractionalBits] = (
            IntegerBits(3),
            FractionalBits(12),
        ),
    ) -> ComplexSeries | None:
        """
        Process Capture Data.
        Returns a list of complex numbers containing the data (I, Q) for each sample.
        """
        if self.capture_data is None:
            return None
        capture_data = FixedPointDecoder.decode_complex_data(
            self.capture_data, sm_n_format
        )
        return capture_data

    def get_cm_symbol_capture(self) -> dict | None:
        return {
            "DS Channel Id": self.channel_id,
            "CM MAC Address": self.mac_address,
            "Subcarrier Zero Frequency": self.subcarrier_zero_frequency,
            "Sample Rate": self.sample_rate,
            "FFT Size": self.fft_size,
            "Trigger Group Id": self.trigger_group_id,
            "Transaction ID": self.transaction_id,
            "Capture Data Length": self.capture_data_length,
            "Capture Data": self.capture_data.hex()
            if self.capture_data is not None
            else None,
        }

    def to_model(self) -> CmSymbolCaptureModel:
        """Convert parsed data to a Pydantic model"""
        return CmSymbolCaptureModel()
