# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pypnm.pnm.parser.pnm_header import PnmHeaderParameters


class PnmFileType(Enum):
    """
    Enumeration of PNM file types, mapping human-readable names to
    4-character PNM CANN codes used in DOCSIS modem telemetry.

    Attributes:
        pnm_cann (str): The PNM CANN code identifying this file type.

    Methods:
        get_pnm_cann(): Return the raw PNM CANN code.
        to_ascii(): Alias for get_pnm_cann (returns ASCII code).
        from_name(name): Class method to lookup an enum by its name.
    """

    SYMBOL_CAPTURE = "PNN1"
    OFDM_CHANNEL_ESTIMATE_COEFFICIENT = "PNN2"
    DOWNSTREAM_CONSTELLATION_DISPLAY = "PNN3"
    RECEIVE_MODULATION_ERROR_RATIO = "PNN4"
    DOWNSTREAM_HISTOGRAM = "PNN5"
    UPSTREAM_PRE_EQUALIZER_COEFFICIENTS = "PNN6"
    UPSTREAM_PRE_EQUALIZER_COEFFICIENTS_LAST_UPDATE = "PNN7"
    OFDM_FEC_SUMMARY = "PNN8"
    SPECTRUM_ANALYSIS = "PNN9"
    OFDM_MODULATION_PROFILE = "PNN10"
    LATENCY_REPORT = "LLD01"

    # (Not in Spec)Internal use for SNMP-based Spectrum Analysis
    CM_SPECTRUM_ANALYSIS_SNMP_AMP_DATA = "PXX9"

    def __init__(self, pnm_cann: str) -> None:
        """
        Initialize the enum member with its PNM CANN code.

        Args:
            pnm_cann (str): 4-character code used by the modem.
        """
        self.pnm_cann: str = pnm_cann

    def get_pnm_cann(self) -> str:
        """
        Retrieve the raw PNM CANN code for this file type.

        Returns:
            str: The 4-character PNM CANN identifier.
        """
        return self.pnm_cann

    def to_ascii(self) -> str:
        """
        Convert the PNM CANN code to its ASCII representation.

        Alias for `get_pnm_cann()`; provided for semantic clarity.

        Returns:
            str: ASCII string of the PNM code.
        """
        return self.get_pnm_cann()

    @classmethod
    def from_name(cls, name: str) -> PnmFileType:
        """
        Lookup a PnmFileType by its enum member name.

        Args:
            name (str): The enum member name (e.g., "SYMBOL_CAPTURE").

        Returns:
            PnmFileType: Corresponding enum member.

        Raises:
            KeyError: If `name` is not a valid member of the enum.
        """
        try:
            return cls[name]
        except KeyError as exc:
            valid = ", ".join([e.name for e in cls])
            raise KeyError(
                f"Invalid PnmFileType name: {name!r}. Valid names: {valid}"
            ) from exc

    @classmethod
    def from_mmnemonic(cls, tag: str, version: int) -> PnmFileType:
        """
        Construct a PNM/PNN/LLD code from (tag, version) and return the enum member.

        Args:
            tag (str): Prefix such as "PNN", "PNM", or "LLD".
            version (int): Version number. For "LLD" the version is zero-padded to 2
                digits (e.g., 1 -> "01"). For "PNN"/"PNM" no padding is applied
                (e.g., 9 -> "9", 10 -> "10").

        Returns:
            PnmFileType: Matching enum member.

        Raises:
            KeyError: If the composed code does not map to any known enum value.
        """
        tag_up = tag.upper()
        if tag_up == "LLD":
            code = f"LLD{version:02d}"

        elif tag_up in ("PNN", "PNM"):
            code = f"{tag_up}{version}"

        else:
            code = f"{tag_up}{version}"

        for member in cls:
            if member.value == code:
                return member

        valid_codes = ", ".join(m.value for m in cls)
        raise KeyError(f"Unknown code: {code!r}. Valid codes: {valid_codes}")

    @classmethod
    def from_tag(cls, code: str) -> PnmFileType:
        """
        Resolve a file type from a full PNM/PNN/LLD tag.

        Accepts values like "PNN9", "PNN10", "PNM2", "LLD1", "LLD01".
        Matching is case-insensitive; surrounding whitespace is ignored.
        For "LLD", a single-digit version is normalized to two digits.

        Args:
            code (str): Full tag code.

        Returns:
            PnmFileType: Matching enum member.

        Raises:
            KeyError: If the tag does not map to a known file type.
        """
        s = code.strip().upper()
        if len(s) < 4:
            raise KeyError(
                f"Unknown code: {code!r}. Provide a full tag like 'PNN9' or 'LLD01'."
            )

        prefix, suffix = s[:3], s[3:]

        # Normalize
        if prefix == "LLD":
            if not suffix.isdigit():
                raise KeyError(f"Unknown code: {code!r}. 'LLD' suffix must be numeric.")
            s = f"LLD{int(suffix):02d}"  # e.g., LLD1 -> LLD01

        elif prefix in ("PNN", "PNM"):
            if not suffix.isdigit():
                raise KeyError(
                    f"Unknown code: {code!r}. '{prefix}' suffix must be numeric."
                )
            s = f"{prefix}{int(suffix)}"  # strip any leading zeros

        # else: leave as-is and try exact match

        for member in cls:
            if member.value == s:
                return member

        valid_codes = ", ".join(m.value for m in cls)
        raise KeyError(
            f"Unknown code: {code!r}. Normalized to {s!r}. Valid codes: {valid_codes}"
        )

    @classmethod
    def fromPnmHeaderModel(cls, params: PnmHeaderParameters) -> PnmFileType:
        """
        Derive a PnmFileType from a parsed PnmHeaderParameters instance.

        This helper inspects the wrapped `pnm_header` parameters and uses
        the file_type + file_type_version pair to resolve the appropriate
        PnmFileType enum member.

        Args:
            params (PnmHeaderParameters): Parsed PNM header parameters.

        Returns:
            PnmFileType: Matching PNM file type enum member.

        Raises:
            KeyError: If the header fields do not map to a known file type, or
                if the file_type field is missing/empty.
        """

        file_type = (params.file_type or "").strip().upper()
        version = params.file_type_version

        if not file_type:
            raise KeyError("PnmHeaderParameters.file_type is missing or empty")

        return cls.from_mmnemonic(file_type, version)
