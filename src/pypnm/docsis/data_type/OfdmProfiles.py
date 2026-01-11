from __future__ import annotations

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia
from enum import Enum


class OfdmProfile(Enum):
    """
    Enum representing OFDM downstream profile identifiers.
    """

    profile0 = 0
    profile1 = 1
    profile2 = 2
    profile3 = 3
    profile4 = 4
    profile5 = 5
    profile6 = 6
    profile7 = 7
    profile8 = 8
    profile9 = 9
    profile10 = 10
    profile11 = 11
    profile12 = 12
    profile13 = 13
    profile14 = 14
    profile15 = 15

    @staticmethod
    def from_index(index: int) -> OfdmProfile:
        for member in OfdmProfile:
            if member.value == index:
                return member
        raise ValueError(f"No OFDM profile enum for index {index}")


class OfdmProfiles:
    """
    Represents a set of active OFDM downstream profiles using a 16-bit bitmask.

    DOCSIS BITS are MSB-first. So profile0 is the most significant bit.
    """

    BITS_16: int = 16

    def __init__(self, bits: int) -> None:
        self.bits = bits

    def list_profiles(self) -> list[OfdmProfile]:
        """
        Return a list of active OFDM profile enum members.

        Returns:
            List[OfdmProfile]: Active profiles (e.g., [OfdmProfile.profile0, OfdmProfile.profile4])
        """
        return [
            OfdmProfile.from_index(bit)
            for bit in range(OfdmProfiles.BITS_16)
            if self.bits & (1 << (15 - bit))  # MSB-first bit position
        ]

    def is_active(self, profile: OfdmProfile) -> bool:
        """
        Check if a specific OFDM profile is active.

        Args:
            profile (OfdmProfile): Enum value to check.

        Returns:
            bool: True if the profile is active, False otherwise.
        """
        return bool(self.bits & (1 << (15 - profile.value)))  # MSB-first

    @staticmethod
    def from_snmp(raw: str | bytes) -> OfdmProfiles:
        """
        Create an OfdmProfiles instance from SNMP raw value.

        Args:
            raw (str or bytes): SNMP value, e.g., "0x8800" or b'\\x88\\x00'.

        Returns:
            OfdmProfiles: Parsed instance.
        """
        if isinstance(raw, bytes):
            value = int.from_bytes(raw, byteorder="big")  # DOCSIS is MSB-first
        elif isinstance(raw, str):
            raw = raw.strip()
            value = int(raw, 16) if raw.startswith("0x") else int(raw)
        else:
            raise TypeError("Expected bytes or string as input")

        return OfdmProfiles(value)

    def to_hex(self) -> str:
        """
        Return the hex representation of the 16-bit bitmask in MSB-first order.

        Returns:
            str: Hex string (e.g., "0x8800")
        """
        return f"0x{self.bits:04X}"

    def __repr__(self) -> str:
        return f"<OfdmProfiles active={[p.name for p in self.list_profiles()]}>"
