# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from struct import calcsize, unpack

from pypnm.lib.mac_address import MacAddress, MacAddressFormat
from pypnm.lib.types import IntSeries, MacAddressStr
from pypnm.pnm.parser.model.parser_rtn_models import CmDsHistModel
from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader


class CmDsHist(PnmHeader):
    """
    Represents the Downstream Histogram data collected from a Cable Modem (CM).

    This histogram provides a measurement of nonlinear effects in the downstream channel,
    such as amplifier compression and laser clipping. The CM captures a time-domain
    signal snapshot and sorts the values into bins (buckets) based on signal level,
    allowing visualization of distortions. This helps technicians identify signal issues.

    The histogram includes:
    - MAC address of the CM
    - Symmetry flag (1 byte, additional signal characterization)
    - Dwell Count: Number of samples considered per bin
    - Hit Count: Number of samples that actually fall into each bin

    The class extracts and exposes this data from binary format for further analysis.
    """

    def __init__(self, binary_data: bytes) -> None:
        super().__init__(binary_data)
        self.logger = logging.getLogger(self.__class__.__name__)

        self._mac_address: MacAddressStr
        self._symmetry: int
        self._dwell_count_values_length: int
        self._dwell_count_values: IntSeries
        self._hit_count_values_length: int
        self._hit_count_values: IntSeries
        self._model: CmDsHistModel

        self.__process()

    def __process(self) -> None:
        if self.get_pnm_file_type() != PnmFileType.DOWNSTREAM_HISTOGRAM:
            cann = PnmFileType.DOWNSTREAM_HISTOGRAM.get_pnm_cann()
            actual_type = self.get_pnm_file_type()
            actual_cann = actual_type.get_pnm_cann() if actual_type else "Unknown"
            raise ValueError(
                f"PNM File Stream is not RxMER file type: {cann}, Error: {actual_cann}"
            )

        mac_sym_format = ">6sB"
        mac_sym_header_size = calcsize(mac_sym_format)

        try:
            unpacked = unpack(mac_sym_format, self.pnm_data[:mac_sym_header_size])
            self._mac_address = MacAddress(unpacked[0]).to_mac_format(
                MacAddressFormat.COLON
            )
            self._symmetry = unpacked[1]
        except Exception as e:
            raise ValueError(f"Failed to unpack header: {e}") from e

        offset = mac_sym_header_size

        # Dwell Count Values
        self._dwell_count_values_length = int.from_bytes(
            self.pnm_data[offset : offset + 4], byteorder="big"
        )
        offset += 4
        count = self._dwell_count_values_length // 4
        self._dwell_count_values = [
            int.from_bytes(self.pnm_data[offset + i * 4 : offset + (i + 1) * 4], "big")
            for i in range(count)
        ]
        offset += self._dwell_count_values_length

        # Hit Count Values
        self._hit_count_values_length = int.from_bytes(
            self.pnm_data[offset : offset + 4], byteorder="big"
        )
        offset += 4
        count = self._hit_count_values_length // 4
        self._hit_count_values = [
            int.from_bytes(self.pnm_data[offset + i * 4 : offset + (i + 1) * 4], "big")
            for i in range(count)
        ]

        self._model = CmDsHistModel(
            pnm_header=self.getPnmHeaderParameterModel(),
            mac_address=self._mac_address,
            symmetry=self._symmetry,
            dwell_count_values_length=self._dwell_count_values_length,
            dwell_count_values=self._dwell_count_values,
            hit_count_values_length=self._hit_count_values_length,
            hit_count_values=self._hit_count_values,
        )

    def to_model(self) -> CmDsHistModel:
        return self._model

    def to_dict(self) -> dict:
        """
        Returns a dictionary containing the summarized histogram data.

        Returns:
            dict: Summary of histogram measurement results.
        """
        return self.to_model().model_dump()

    def to_json(self, indent: int = 2) -> str:
        """
        Returns a JSON-formatted string of the summarized histogram data.

        Returns:
            str: JSON representation of the histogram summary.
        """
        return self.to_model().model_dump_json(indent=indent)
