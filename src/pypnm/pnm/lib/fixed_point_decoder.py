# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
from typing import Literal, NewType

from pypnm.lib.types import ComplexSeries

logger = logging.getLogger(__name__)

IntegerBits = NewType("IntegerBits", int)
FractionalBits = NewType("FractionalBits", int)
EndianLiteral = Literal["little", "big"]


class FixedPointDecoder:
    @staticmethod
    def decode_fixed_point(
        value: int, q_format: tuple[IntegerBits, FractionalBits], signed: bool = True
    ) -> float:
        """
        Converts a fixed-point integer value to a floating-point number using the specified Q-format.

        Args:
            value (int): The raw integer value representing a fixed-point number.
            q_format (Tuple[int, int]): A tuple (a, b) where:
                - a = number of integer bits (excluding sign bit)
                - b = number of fractional bits
            signed (bool): Whether to interpret the value as a signed two's complement number.

        Returns:
            float: The decoded floating-point value.
        """
        int_bits, frac_bits = q_format
        total_bits = int_bits + frac_bits + 1  # Includes the sign bit

        if signed:
            sign_bit_mask = 1 << (total_bits - 1)
            if value & sign_bit_mask:
                value -= 1 << total_bits  # Convert from two's complement

        return value / (2**frac_bits)

    @staticmethod
    def decode_complex_data(
        data: bytes,
        q_format: tuple[IntegerBits, FractionalBits],
        signed: bool = True,
        *,
        endian: EndianLiteral = "big",
    ) -> ComplexSeries:
        """
        Decodes a binary byte stream containing fixed-point complex numbers into a list of Python complex numbers.

        Each complex number is composed of:
            - real part (fixed-point)
            - imaginary part (fixed-point)

        The fixed-point format is defined by the Q-format (a, b), and values must be byte-aligned.

        Args:
            data (bytes): The raw byte stream containing complex fixed-point values.
            q_format (Tuple[int, int]): A tuple (a, b) specifying the Q-format.
            signed (bool): Whether the fixed-point numbers should be interpreted as signed.
            endian (Literal["little","big"]): Byte order to use when decoding each component.

        Returns:
            List[complex]: A list of decoded complex numbers.
        """
        int_bits, frac_bits = q_format
        total_bits = int_bits + frac_bits + 1

        if total_bits % 8 != 0:
            raise ValueError(
                f"Unsupported Q-format: total bits ({total_bits}) must be a multiple of 8."
            )

        bytes_per_component = total_bits // 8
        bytes_per_complex = 2 * bytes_per_component

        if len(data) % bytes_per_complex != 0:
            raise ValueError(
                "Invalid input: data length must be a multiple of the complex number size."
            )

        complex_values: list[complex] = []

        mv = memoryview(data)
        for offset in range(0, len(data), bytes_per_complex):
            real_bytes = mv[offset : offset + bytes_per_component]
            imag_bytes = mv[offset + bytes_per_component : offset + bytes_per_complex]

            real_int = int.from_bytes(real_bytes, byteorder=endian, signed=False)
            imag_int = int.from_bytes(imag_bytes, byteorder=endian, signed=False)

            real = FixedPointDecoder.decode_fixed_point(real_int, q_format, signed)
            imag = FixedPointDecoder.decode_fixed_point(imag_int, q_format, signed)

            complex_number = complex(real, imag)
            complex_values.append(complex_number)

            logger.debug(
                f"Decoded complex ({endian}-endian): raw_real=0x{real_int:X}, raw_imag=0x{imag_int:X}, "
                f"float=({real:.6f} + {imag:.6f})"
            )

        return complex_values
