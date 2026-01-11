# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import ipaddress
import logging

from pypnm.lib.types import InetAddressStr


class InetGenerate:
    """
    A utility class for operations related to IP addresses, such as conversion and version checking.
    """

    @staticmethod
    def ipv4_to_hex(ipv4_address: str) -> str:
        """
        Convert an IPv4 address to its hexadecimal representation.

        Args:
            ipv4_address (str): The IPv4 address to convert.

        Returns:
            str: The hexadecimal representation of the IPv4 address.

        Example:
            ipv4_to_hex('192.168.0.1') -> '0xC0 0xA8 0x00 0x01'
        """
        return " ".join(f"0x{int(octet, 10):02X}" for octet in ipv4_address.split("."))

    @staticmethod
    def inet_to_binary(inet: str) -> bytes | None:
        """
        Convert an IP address (IPv4 or IPv6) to its binary representation.

        Args:
            inet_address (str): The IP address to convert.

        Returns:
            Optional[bytes]: The binary representation of the IP address, or None if the address is invalid.
        """
        try:
            ip_obj = ipaddress.ip_address(inet)
            return ip_obj.packed
        except ValueError:
            return None

    @staticmethod
    def binary_to_inet(binary_address: bytes) -> str | None:
        """
        Convert a binary representation of an IP address (IPv4 or IPv6) back to its string format.

        Args:
            binary_address (bytes): The binary representation of the IP address.

        Returns:
            Optional[str]: The string representation of the IP address, or None if the binary data is invalid.
        """
        try:
            # Use ipaddress.ip_address to convert the binary address to a string format
            ip_obj = ipaddress.ip_address(binary_address)
            # Return the string representation of the IP address
            return str(ip_obj)
        except ValueError:
            # If the binary data is invalid, return None
            logging.error(f"Invalid binary address: {binary_address}")
            return None

    @staticmethod
    def are_inets_same_version(inet1: str, inet2: str) -> bool:
        """
        Check if two IP addresses have the same IP version (IPv4 or IPv6).

        Args:
            host (str): The first IP address to compare.
            tftp (str): The second IP address to compare.

        Returns:
            bool: True if both IP addresses have the same version, otherwise False.
        """
        try:
            host_type = ipaddress.ip_address(inet1).version
            tftp_type = ipaddress.ip_address(inet2).version
            return host_type == tftp_type
        except ValueError:
            return False

    @staticmethod
    def get_inet_version(inet: InetAddressStr) -> str:
        """
        Get the IP version of the provided IP address.

        Args:
            ip_address (str): The IP address to check.

        Returns:
            str: The IP version ('IPv4' or 'IPv6').

        Raises:
            SystemExit: If the provided IP address is invalid.
        """
        try:
            ip_obj = ipaddress.ip_address(inet)
            return "IPv4" if ip_obj.version == 4 else "IPv6"
        except ValueError:
            raise ValueError(f"Invalid IP address: {inet}") from None

    @staticmethod
    def hex_to_inet(inet_hex_str: str) -> str:
        """
        Convert a HEX string to an IP address (IPv4 or IPv6).

        Args:
            hex_str (str): The HEX string representing an IP address (without spaces or delimiters).

        Returns:
            str: The IP address in standard notation (IPv4 or IPv6).

        Raises:
            ValueError: If the HEX string is invalid or the length is incorrect for both IPv4 and IPv6 addresses.
        """
        # Ensure the HEX string is valid
        if not isinstance(inet_hex_str, str) or len(inet_hex_str) == 0:
            raise ValueError("Input must be a non-empty string.")

        # Remove spaces and validate length
        inet_hex_str = inet_hex_str.replace(" ", "").lower()

        # Check if the length of the hex string is 8 (IPv4) or 32 (IPv6)
        if len(inet_hex_str) == 8:  # IPv4 address
            try:
                # Convert HEX string to bytes and then to an IPv4 address
                ip_bytes = bytes.fromhex(inet_hex_str)
                ip_address = ipaddress.IPv4Address(ip_bytes)
                return str(ip_address)
            except ValueError:
                raise ValueError(
                    f"Invalid HEX string for IPv4: {inet_hex_str}"
                ) from None
        elif len(inet_hex_str) == 32:  # IPv6 address
            try:
                # Convert HEX string to bytes and then to an IPv6 address
                ip_bytes = bytes.fromhex(inet_hex_str)
                ip_address = ipaddress.IPv6Address(ip_bytes)
                return str(ip_address)
            except ValueError:
                raise ValueError(
                    f"Invalid HEX string for IPv6: {inet_hex_str}"
                ) from None
        else:
            raise ValueError(
                "HEX string must represent either a valid IPv4 (8 hex characters) or IPv6 (32 hex characters) address."
            )
