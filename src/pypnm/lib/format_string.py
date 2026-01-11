# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import string
from collections.abc import Iterable
from typing import Any


class Format:
    @staticmethod
    def join_paren(
        values: Iterable[Any] | None, sep: str = ", ", empty: str = "—"
    ) -> str:
        """
        Join items into a comma-separated string wrapped in parentheses.
        Uses only built-ins (str(), join) and strict typing.
        """
        if not values:
            return f"({empty})"
        items = (str(v) for v in values)
        return f"({sep.join(items)})"

    @staticmethod
    def hex_string(hex_string: str, delimiter: str = ":", grouping: int = 2) -> str:
        """
        Format a hexadecimal string by grouping and separating with a custom delimiter.

        This method normalizes a hex string (e.g., from "0x1a2b3c4d" or "1a2b 3c4d") and applies
        a delimiter to format it in a readable way.

        Parameters:
            hex_string (str): The input hexadecimal string. Can include "0x" prefix or spaces.
            delimiter (str, optional): Character to insert between hex groups (default is ':').
            grouping (int, optional): Number of hex characters per group (default is 2).

        Returns:
            str: The formatted hex string.

        Example:
            ```python
            formatted = Format.hex_string("0x1a2b3c4d")
            print(formatted)  # Output: '1a:2b:3c:4d'
            ```
        """
        # Remove "0x" prefix and all spaces or previous delimiters
        hex_string = (
            hex_string.replace("0x", "").replace(delimiter, "").replace(" ", "")
        )

        # Group hex characters and join with the specified delimiter
        grouped_hex = [
            hex_string[i : i + grouping] for i in range(0, len(hex_string), grouping)
        ]
        return delimiter.join(grouped_hex)

    @staticmethod
    def non_ascii_to_hex(value: str | bytes | object) -> str:
        """
        Convert a string or bytes to ASCII if possible; otherwise return a hex representation.

        This method is useful for safely logging or displaying binary or encoded data
        by converting unprintable or non-ASCII characters into a hexadecimal string.

        Parameters:
            value (str | bytes | object): The input value to normalize.

        Returns:
            str: Printable ASCII string if all characters are ASCII-printable;
                 otherwise a hex-encoded representation of the input.

        Example:
            ```python
            Format.non_ascii_to_hex("Hello")           # Output: "Hello"
            Format.non_ascii_to_hex(b'\xff\xfa')       # Output: "fffa"
            Format.non_ascii_to_hex("あいうえお")     # Output: "e38182e38184e38186e38188e3818a"
            ```
        """
        if isinstance(value, bytes):
            try:
                decoded = value.decode("ascii")
                if all(c in string.printable for c in decoded):
                    return decoded
                else:
                    return value.hex()
            except UnicodeDecodeError:
                return value.hex()
        elif isinstance(value, str):
            if all(c in string.printable for c in value):
                return value
            else:
                return value.encode("utf-8").hex()
        else:
            return str(value)
