# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from pypnm.lib.inet_utils import InetGenerate
from pypnm.lib.types import InetAddressStr


class Inet:
    """
    A class to represent an IP address and check its version.

    Attributes:
        _inet (str): The validated IP address.
    """

    def __init__(self, inet: InetAddressStr) -> None:
        """
        Initializes the Inet class with an IP address.

        Args:
            inet (str): The IP address.

        Raises:
            ValueError: If the IP address is invalid.
        """
        if not InetGenerate.get_inet_version(
            inet
        ):  # Assuming it returns version or raises
            raise ValueError(f"Invalid IP address: {inet}")
        self._inet = inet

    @property
    def inet(self) -> str:
        """Returns the stored IP address."""
        return self._inet

    def same_inet_version(self, other: Inet) -> bool:
        """
        Checks if another Inet instance has the same IP version.

        Args:
            other (Inet): Another Inet object.

        Returns:
            bool: True if both IPs are of the same version (IPv4/IPv6).
        """
        return InetGenerate.are_inets_same_version(self._inet, other._inet)

    def __eq__(self, other: object) -> bool:
        """Equality comparison for two Inet objects."""
        if not isinstance(other, Inet):
            return NotImplemented
        return self._inet == other._inet

    def __hash__(self) -> int:
        """Returns a hash based on the IP address."""
        return hash(self._inet)

    def __str__(self) -> str:
        """Returns the string representation of the IP address."""
        return self._inet
