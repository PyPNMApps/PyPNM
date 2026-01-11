# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from struct import calcsize, unpack
from typing import cast

from pypnm.lib.constants import KHZ
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import ChannelId, ComplexArray, FrequencyHz, MacAddressStr
from pypnm.pnm.lib.fixed_point_decoder import (
    FixedPointDecoder,
    FractionalBits,
    IntegerBits,
)
from pypnm.pnm.parser.model.parser_rtn_models import CmDsConstDispMeasModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader


class CmDsConstDispMeas(PnmHeader):
    """
    Parses and processes Downstream Constellation Display Measurement (CmDsConstDispMeas) data.
    Inherits from PnmHeader to handle binary SNMP-based CM measurement data.
    """

    CONST_DISPLAY_DATA_COMPLEX_LENGTH: int = 4

    def __init__(self, binary_data: bytes) -> None:
        """
        Initializes the CmDsConstDispMeas instance and parses the binary payload.

        Args:
            binary_data (bytes): Raw binary data from SNMP or TFTP source.
        """
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)

        self._channel_id: ChannelId
        self._mac_address: MacAddressStr
        self._subcarrier_zero_frequency: FrequencyHz
        self._actual_modulation_order: int
        self._num_sample_symbols: int
        self._subcarrier_spacing: FrequencyHz
        self._display_data_length: int
        self._constellation_display_data: bytes
        self._parsed_constellation_data: ComplexArray
        self._model: CmDsConstDispMeasModel

        self.__process()

    def __process(self) -> None:
        """
        Parses the binary payload for constellation display measurement.

        Expected binary format:
            - 1 byte: channel ID
            - 6 bytes: CM MAC address
            - 4 bytes: subcarrier zero frequency    (Hz)
            - 2 bytes: actual modulation order      (DsOfdmModulationType)
            - 2 bytes: number of sample symbols
            - 1 byte:  subcarrier spacing           (kHz)
            - 4 bytes: display data length          (bytes)
            - N bytes: constellation display data   (complex samples)
        """

        if self.get_pnm_file_type() != PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY:
            cann = PnmFileType.DOWNSTREAM_CONSTELLATION_DISPLAY.get_pnm_cann()
            current_type = self.get_pnm_file_type()
            error_cann = (
                current_type.get_pnm_cann() if current_type is not None else "Unknown"
            )
            raise ValueError(
                f"PNM File Stream is not RxMER file type: {cann}, Error: {error_cann}"
            )

        const_disp_meas_format = ">B6sIHHBI"
        const_disp_meas_size = calcsize(const_disp_meas_format)
        unpacked_data = unpack(
            const_disp_meas_format, self.pnm_data[:const_disp_meas_size]
        )

        self._channel_id = ChannelId(unpacked_data[0])
        self._mac_address = MacAddress(unpacked_data[1]).to_mac_format(
            MacAddressFormat.COLON
        )
        self._subcarrier_zero_frequency = FrequencyHz(unpacked_data[2])
        self._actual_modulation_order = unpacked_data[3]
        self._num_sample_symbols = unpacked_data[4]
        self._subcarrier_spacing = FrequencyHz(unpacked_data[5] * KHZ)
        self._display_data_length = unpacked_data[6]
        self._constellation_display_data = self.pnm_data[const_disp_meas_size:]

        self._model = CmDsConstDispMeasModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            channel_id=self._channel_id,
            mac_address=self._mac_address,
            subcarrier_zero_frequency=self._subcarrier_zero_frequency,
            subcarrier_spacing=self._subcarrier_spacing,
            actual_modulation_order=self._actual_modulation_order,
            num_sample_symbols=self._num_sample_symbols,
            sample_length=self._display_data_length,
            samples=self._process_constellation_display_data(),
        )

    def _process_constellation_display_data(self) -> ComplexArray:
        """
        Decodes the constellation display binary data into a list of [i, q] float pairs.

        This reduced format is optimized for REST payload transmission.

        Returns:
            List of [i, q] float pairs.
        """
        offset = 0
        raw: bytes = self._constellation_display_data
        decode_list = []

        while offset + self.CONST_DISPLAY_DATA_COMPLEX_LENGTH <= len(raw):
            decoded = FixedPointDecoder.decode_complex_data(
                raw[offset : offset + 4],
                cast(tuple[IntegerBits, FractionalBits], (2, 13)),
            )

            decode_list.extend([[float(pt.real), float(pt.imag)] for pt in decoded])

            offset += 4

        return decode_list

    def to_model(self) -> CmDsConstDispMeasModel:
        return self._model

    def to_dict(self) -> dict[str, object | None]:
        """
        Returns:
            dict: Alias for `get_const_disp_meas()`.
        """
        return self.to_model().model_dump()

    def to_json(self, indent: int = 2) -> str:
        """
        Serializes the parsed measurement data to a JSON string.

        Returns:
            str: JSON-formatted string representation of the data.
        """
        return self.to_model().model_dump_json(indent=indent)
