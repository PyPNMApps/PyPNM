# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import math


class DocsEqualizerData:
    """
    Parses and holds DOCSIS Equalizer Data from SNMP binary input.

    Format based on DOCSIS RFI v2.0:
    - 1 byte: Main tap location
    - 1 byte: Forward taps per symbol
    - 1 byte: Number of forward taps (n)
    - 1 byte: Number of reverse taps (m)
    - Followed by 4*n bytes for forward tap complex coefficients
    - Followed by 4*m bytes for reverse tap complex coefficients
    Each coefficient is 2 bytes (int16) for real and 2 bytes for imaginary parts.
    """

    HEADER_SIZE = 4
    TAP_BYTES = 4
    MAX_TAPS = 64
    MIN_TOTAL_BYTES = HEADER_SIZE + TAP_BYTES * 8
    MAX_TOTAL_BYTES = HEADER_SIZE + TAP_BYTES * MAX_TAPS
    COEFF_BYTES = 2
    COMPLEX_TAP_SIZE = COEFF_BYTES * 2

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        self._coefficients_found: bool = False
        self.equalizer_data: dict[int, dict] = {}

    def add(self, us_idx: int, hex_data: str) -> bool:
        """
        Parses and stores equalizer coefficients for a given upstream index.

        :param us_idx: Upstream channel index
        :param hex_data: Hexadecimal string representing the equalizer data
        :return: True if successfully parsed and stored
        """
        try:
            binary_data = bytes.fromhex(hex_data.replace("0x", ""))
            if not (self.MIN_TOTAL_BYTES <= len(binary_data) <= self.MAX_TOTAL_BYTES):
                self.logger.warning(
                    f"Invalid data size ({len(binary_data)} bytes) for upstream index {us_idx}"
                )
                return False

            main_tap = binary_data[0]
            fwd_taps_per_sym = binary_data[1]
            num_forward = binary_data[2]
            num_reverse = binary_data[3]

            total_taps = num_forward + num_reverse
            if total_taps > self.MAX_TAPS:
                self.logger.error(
                    f"Exceeded max tap count ({total_taps}) for index {us_idx}"
                )
                return False

            offset = self.HEADER_SIZE
            forward_coeffs = self._parse_coefficients(
                binary_data[offset : offset + num_forward * self.TAP_BYTES]
            )
            offset += num_forward * self.TAP_BYTES
            reverse_coeffs = self._parse_coefficients(
                binary_data[offset : offset + num_reverse * self.TAP_BYTES]
            )

            self.equalizer_data[us_idx] = {
                "main_tap_location": main_tap,
                "forward_taps_per_symbol": fwd_taps_per_sym,
                "num_forward_taps": num_forward,
                "num_reverse_taps": num_reverse,
                "forward_coefficients": forward_coeffs,
                "reverse_coefficients": reverse_coeffs,
            }

            self._coefficients_found = True
            self.logger.debug(f"Parsed equalizer data for upstream index {us_idx}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to parse equalizer data for index {us_idx}: {e}")
            return False

    def _parse_coefficients(self, data: bytes) -> list[dict[str, float]]:
        coeffs = []
        for i in range(0, len(data), self.COMPLEX_TAP_SIZE):
            real = int.from_bytes(
                data[i : i + self.COEFF_BYTES], byteorder="big", signed=True
            )
            imag = int.from_bytes(
                data[i + self.COEFF_BYTES : i + self.COMPLEX_TAP_SIZE],
                byteorder="big",
                signed=True,
            )
            magnitude = math.sqrt(real**2 + imag**2)
            power_db = 10 * math.log10(magnitude**2) if magnitude > 0 else None

            coeff = {
                "real": real,
                "imag": imag,
                "magnitude": round(magnitude, 2),
                "magnitude_power_dB": round(power_db, 2)
                if power_db is not None
                else None,
            }
            coeffs.append(coeff)
        return coeffs

    def coefficients_found(self) -> bool:
        return self._coefficients_found

    def to_dict(self) -> dict[int, dict]:
        return self.equalizer_data

    def to_json(self, indent: int = 2) -> str:
        import json

        return json.dumps(self.to_dict(), indent=indent)
