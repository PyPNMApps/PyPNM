# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from struct import calcsize, unpack
from typing import Any, cast

from pypnm.lib.constants import KHZ
from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import (
    ChannelId,
    ComplexArray,
    ComplexSeries,
    FrequencyHz,
    MacAddressStr,
)
from pypnm.pnm.lib.fixed_point_decoder import (
    FixedPointDecoder,
    FractionalBits,
    IntegerBits,
)
from pypnm.pnm.parser.model.parser_rtn_models import CmUsOfdmaPreEqModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader


class CmUsOfdmaPreEq(PnmHeader):
    """
    Parses and decodes CM OFDMA Upstream Pre-Equalization data from binary input.

    Produces a validated `CmUsOfdmaPreEqModel` that includes:
      - PNM header fields (via PnmBaseModel)
      - CM/CMTS MAC addresses
      - Channel/frequency metadata (subcarrier 0, first active index, spacing in Hz)
      - Complex pre-equalization coefficients as [real, imag] pairs

      - The CM Pre-Equalizer coefficients are expressed as 16-bit two's complement numbers using s2.13 format.
      - The Pre-Equalizer coefficient "update values" sent to the CM by the CMTS are expressed as 16-bit
        two's complement numbers using S1.14 format

    """

    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)
        self._channel_id: ChannelId
        self._mac_address: MacAddressStr
        self._cmts_mac_address: MacAddressStr
        self._subcarrier_zero_frequency: FrequencyHz
        self._first_active_subcarrier_index: int
        self._subcarrier_spacing: FrequencyHz
        self._pre_eq_data_length: int
        self._pre_eq_coefficient_data: bytes
        self._decoded_coefficients: ComplexSeries
        self._occupied_channel_bandwidth: FrequencyHz
        self._model: CmUsOfdmaPreEqModel
        self._sm_n_format: tuple[IntegerBits, FractionalBits]

        self.__process()

    def __process(self) -> None:
        """
        Parse header and coefficient block; decode fixed-point complex values; build BaseModel.
        Header format (big-endian):
            >B 6s 6s I H B I
             | |  |  | | | +-- pre-eq data length (bytes)
             | |  |  | | +---- subcarrier spacing (kHz, 1-byte)
             | |  |  | +------ first active subcarrier index (H)
             | |  |  +-------- subcarrier zero frequency (Hz, I)
             | |  +----------- CMTS MAC (6s)
             | +-------------- CM MAC (6s)
             +---------------- upstream channel id (B)
        """
        # Validate file type (allow "last update" variant)
        file_type = self.get_pnm_file_type()
        if (file_type != PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS) and (
            file_type != PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE
        ):
            expected = PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS.get_pnm_cann()
            got = file_type.get_pnm_cann() if file_type is not None else "None"
            raise ValueError(
                f"PNM File Stream is not file type: {expected}, Error: {got}"
            )

        if file_type == PnmFileType.UPSTREAM_PRE_EQUALIZER_COEFFICIENTS:
            self._sm_n_format = (IntegerBits(1), FractionalBits(14))
            debug_msg = (
                "Using s2.13 format for Upstream Pre-Equalizer Coefficients PNM data."
            )
        else:
            self._sm_n_format = (IntegerBits(1), FractionalBits(14))
            debug_msg = "Using s1.14 format for Upstream Pre-Equalizer Coefficients Last Update PNM data."

        self.logger.debug(debug_msg)

        header_format = ">B6s6sIHBI"
        header_size = calcsize(header_format)
        if len(self.pnm_data) < header_size:
            raise ValueError("Insufficient data for CmUsOfdmaPreEq header.")

        (
            self._channel_id,
            cm_mac,
            cmts_mac,
            self._subcarrier_zero_frequency,
            self._first_active_subcarrier_index,
            subcarrier_spacing_khz,
            self._pre_eq_data_length,
        ) = unpack(header_format, self.pnm_data[:header_size])

        self._mac_address = MacAddress(cm_mac).to_mac_format(MacAddressFormat.COLON)
        self._cmts_mac_address = MacAddress(cmts_mac).to_mac_format(
            MacAddressFormat.COLON
        )
        self._pre_eq_coefficient_data = self.pnm_data[header_size:]
        self._subcarrier_spacing = subcarrier_spacing_khz * KHZ

        if len(self._pre_eq_coefficient_data) != self._pre_eq_data_length:
            raise ValueError(
                f"Mismatch between reported ({self._pre_eq_data_length}) and actual ({len(self._pre_eq_coefficient_data)}) Pre-EQ data length."
            )

        # Decode fixed-point complex coefficients → List[complex]
        decoded: ComplexSeries = self.process_pre_eq_coefficient_data()
        if not decoded:
            raise ValueError("No pre-equalization coefficients decoded.")

        # Convert to ComplexArray: List[List[float, float]]
        complex_pairs: ComplexArray = cast(
            ComplexArray, [[c.real, c.imag] for c in decoded]
        )

        self._model = CmUsOfdmaPreEqModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            channel_id=self._channel_id,
            mac_address=self._mac_address,
            subcarrier_zero_frequency=self._subcarrier_zero_frequency,
            first_active_subcarrier_index=int(self._first_active_subcarrier_index),
            subcarrier_spacing=self._subcarrier_spacing,
            occupied_channel_bandwidth=self._cal_occ_bw(),
            cmts_mac_address=self._cmts_mac_address,
            value_length=int(self._pre_eq_data_length),
            value_unit="[Real, Imaginary]",
            values=complex_pairs,
        )

    def _cal_occ_bw(self) -> FrequencyHz:
        """
        Calculate Occupied Channel Bandwidth (Hz).
        """
        return FrequencyHz(len(self._decoded_coefficients) * self._subcarrier_spacing)

    def process_pre_eq_coefficient_data(self) -> ComplexSeries:
        """
        Decode fixed-point complex coefficients using (s,m.n) format.
        """
        if not self._pre_eq_coefficient_data:
            return []

        self._decoded_coefficients = FixedPointDecoder.decode_complex_data(
            self._pre_eq_coefficient_data,
            self._sm_n_format,
        )
        return self._decoded_coefficients

    def get_coefficients(self) -> ComplexSeries:
        """
        Return previously decoded coefficients if available; otherwise decode on demand.
        """
        if self._decoded_coefficients is not None:
            return self._decoded_coefficients
        return self.process_pre_eq_coefficient_data()

    def to_model(self) -> CmUsOfdmaPreEqModel:
        return self._model

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to a plain dictionary via the Pydantic model.
        """
        return self._model.model_dump()

    def to_json(self, indent: int = 2) -> str:
        """
        Convert to a JSON string via the Pydantic model.
        """
        return self._model.model_dump_json(indent=indent)

    def __repr__(self) -> str:
        return f"<CmUsOfdmaPreEq(chid={self._channel_id}, cm={self._mac_address}, cmts={self._cmts_mac_address})>"
