# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import logging
import struct
from typing import cast

from pypnm.lib.constants import (
    INVALID_CHANNEL_ID,
    INVALID_SUB_CARRIER_ZERO_FREQ,
    KHZ,
    ZERO_FREQUENCY,
)
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.signal_processing.shan.series import ShannonSeries
from pypnm.lib.types import (
    ChannelId,
    FloatSeries,
    FrequencyHz,
    FrequencySeriesHz,
    MacAddressStr,
)
from pypnm.pnm.lib.signal_statistics import SignalStatistics
from pypnm.pnm.parser.model.parser_rtn_models import CmDsOfdmRxMerModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader


class CmDsOfdmRxMer(PnmHeader):
    """
    Parser and container for DOCSIS 3.1 CM Downstream OFDM RxMER binary data.
    """

    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._rxmer_model: CmDsOfdmRxMerModel

        self._channel_id: ChannelId = INVALID_CHANNEL_ID
        self._mac_address: MacAddressStr = MacAddress.null()
        self._subcarrier_zero_frequency: FrequencyHz = INVALID_SUB_CARRIER_ZERO_FREQ
        self._first_active_subcarrier_index: int = 0
        self._subcarrier_spacing: FrequencyHz = ZERO_FREQUENCY
        self._rxmer_data_length: int = 0
        self._rxmer_data: bytes
        self._rx_mer_float_data: FloatSeries = []

        self._process()

    def _process(self) -> None:
        # Robust non-RxMER rejection (avoid AttributeError if file type is None)
        ft = self.get_pnm_file_type()
        if ft != PnmFileType.RECEIVE_MODULATION_ERROR_RATIO:
            expected = PnmFileType.RECEIVE_MODULATION_ERROR_RATIO.get_pnm_cann()
            actual = ft.get_pnm_cann() if isinstance(ft, PnmFileType) else str(ft)
            raise ValueError(
                f"PNM File Stream is not RxMER file type: {expected}, Error: {actual}"
            )

        try:
            rxmer_data_format = "!B6sIHBI"  # channel_id, mac(6), zero_freq, active_idx, spacing(kHz), data_len
            head_len: int = struct.calcsize(rxmer_data_format)

            if len(self.pnm_data) < head_len:
                raise ValueError("Binary data too short to contain RxMER header.")

            unpacked_data = struct.unpack(rxmer_data_format, self.pnm_data[:head_len])

            self._channel_id = unpacked_data[0]
            self._mac_address = MacAddress(unpacked_data[1]).to_mac_format(
                MacAddressFormat.COLON
            )
            self._subcarrier_zero_frequency = unpacked_data[2]
            self._first_active_subcarrier_index = unpacked_data[3]
            self._subcarrier_spacing = unpacked_data[4] * KHZ
            self._rxmer_data_length = unpacked_data[5]
            self._rxmer_data = self.pnm_data[
                head_len : head_len + self._rxmer_data_length
            ]

            if len(self._rxmer_data) < self._rxmer_data_length:
                raise ValueError(
                    f"Insufficient RxMER data length: {len(self._rxmer_data)} "
                    f"based on header field: {self._rxmer_data_length}"
                )

            self._rxmer_model = self._update_model()

        except struct.error as e:
            self.logger.error(f"Struct unpack error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error processing RxMER data: {e}")
            raise

    def _update_model(self) -> CmDsOfdmRxMerModel:
        values = self.get_rxmer_values()

        model = CmDsOfdmRxMerModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            channel_id=self._channel_id,
            mac_address=self._mac_address,
            subcarrier_zero_frequency=self._subcarrier_zero_frequency,
            first_active_subcarrier_index=self._first_active_subcarrier_index,
            subcarrier_spacing=self._subcarrier_spacing,
            data_length=self._rxmer_data_length,
            occupied_channel_bandwidth=FrequencyHz(
                self._rxmer_data_length * self._subcarrier_spacing
            ),
            values=values,
            signal_statistics=SignalStatistics(values).compute(),
            modulation_statistics=ShannonSeries(values).to_dict(),
        )

        return model

    def get_rxmer_values(self) -> FloatSeries:
        if self._rx_mer_float_data:
            self.logger.debug(f"RxMER Float Data: {self._rx_mer_float_data}")
            return self._rx_mer_float_data

        if not self._rxmer_data:
            self.logger.error("RxMER data is empty or uninitialized.")
            return []

        # quarter-dB -> clamp to [0.0, 63.5]
        self._rx_mer_float_data = [
            min(max(byte / 4.0, 0.0), 63.5) for byte in self._rxmer_data
        ]
        self.logger.debug(f"Decoded {len(self._rx_mer_float_data)} RxMER float values.")
        return self._rx_mer_float_data

    def get_frequencies(self) -> FrequencySeriesHz:
        spacing = int(self._subcarrier_spacing)
        f_zero = int(self._subcarrier_zero_frequency)
        first_idx = int(self._first_active_subcarrier_index)
        n = int(self._rxmer_data_length)

        if spacing <= 0 or n <= 0:
            return []

        start = f_zero + spacing * first_idx
        return cast(FrequencySeriesHz, [start + i * spacing for i in range(n)])

    def to_model(self) -> CmDsOfdmRxMerModel:
        return self._rxmer_model

    def to_dict(self) -> dict[str, object]:
        return self.to_model().model_dump()

    def to_json(self) -> str:
        return self.to_model().model_dump_json()
