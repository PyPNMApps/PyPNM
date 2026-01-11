# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import struct
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, Field

from pypnm.lib.constants import DEFAULT_CAPTURE_TIME
from pypnm.lib.types import CaptureTime
from pypnm.pnm.parser.pnm_file_type import PnmFileType


class PnmHeaderParameters(BaseModel):
    """Typed fields parsed from a PNM header."""

    file_type: str | None = Field(
        default="PNN", description="PNM file type identifier (e.g., 'PNN')"
    )
    file_type_version: int = Field(
        default=0, description="Numeric version of the file type (e.g., 10 for PNN10)"
    )
    major_version: int = Field(default=1, description="Major version of the PNM format")
    minor_version: int = Field(default=0, description="Minor version of the PNM format")
    capture_time: CaptureTime = Field(
        default=DEFAULT_CAPTURE_TIME,
        description="Capture timestamp as epoch seconds since 1970-01-01",
    )


class PnmHeaderModel(BaseModel):
    """Model wrapper for PNM header parameters."""

    pnm_header: PnmHeaderParameters


class PnmHeader:
    """
    Parser for PNM headers.

    Formats
    -------
    - Special (little-endian) when byte_array[3] == 8:
        '<3sBBB'  -> file_type(3s), file_type_num(u8), major(u8), minor(u8)
        (no capture_time)
    - Standard (big-endian/network) otherwise:
        '!3sBBBI' -> file_type(3s), file_type_num(u8), major(u8), minor(u8), capture_time(u32)
    """

    _FMT_LE: str = "<3sBBB"  # special case (no capture_time)
    _FMT_BE: str = "!3sBBBI"  # standard (with capture_time)

    # File types that omit capture_time in their header
    _MISSING_CAPTURE_TYPES = {
        PnmFileType.OFDM_FEC_SUMMARY.value
    }  # FEC Summary file type(s)

    def __init__(self, byte_array: bytes) -> None:
        """
        Initialize and parse a PNM header from raw bytes.

        Args
        ----
        byte_array : bytes
            Raw file bytes starting at the PNM header.
        """
        self.logger: logging.Logger = logging.getLogger(self.__class__.__name__)

        self._pnmheader_model: PnmHeaderModel
        self._parameters: PnmHeaderParameters
        self._file_type: bytes | None = None
        self._file_type_num: int = -1
        self._major_version: int = -1
        self._minor_version: int = -1
        self._capture_time: CaptureTime = DEFAULT_CAPTURE_TIME
        self.pnm_data: bytes = b""

        self.__parse_header(byte_array)
        self.__build_pnm_header_model()

    def __parse_header(self, byte_array: bytes) -> None:
        """
        Internal: parse header fields and slice payload.

        Raises
        ------
        ValueError
            If byte_array is too short to contain a valid header.
        """
        if not isinstance(byte_array, (bytes, bytearray)) or len(byte_array) < 4:
            raise ValueError("byte_array must be bytes-like and at least 4 bytes long")

        special: int = struct.unpack("<B", byte_array[3:4])[0]

        # OFDM_FEC_SUMMARY (PNN8) files do not include capture_time
        if special == 8:
            fmt = self._FMT_LE
            size = struct.calcsize(fmt)
            if len(byte_array) < size:
                raise ValueError("insufficient bytes for little-endian header")
            (
                self._file_type,
                self._file_type_num,
                self._major_version,
                self._minor_version,
            ) = struct.unpack(fmt, byte_array[:size])
        else:
            fmt = self._FMT_BE
            size = struct.calcsize(fmt)
            if len(byte_array) < size:
                raise ValueError("insufficient bytes for big-endian header")
            (
                self._file_type,
                self._file_type_num,
                self._major_version,
                self._minor_version,
                self._capture_time,
            ) = struct.unpack(fmt, byte_array[:size])

        self.pnm_data = bytes(byte_array[size:])

    def __build_pnm_header_model(self) -> None:
        """Build the internal Pydantic model representation of the parsed header."""
        self._parameters = PnmHeaderParameters(
            file_type=self._file_type.decode("utf-8").strip()
            if self._file_type
            else None,
            file_type_version=self._file_type_num,
            major_version=self._major_version,
            minor_version=self._minor_version,
            capture_time=self._capture_time,
        )
        self._pnmheader_model = PnmHeaderModel(pnm_header=self._parameters)

    def getPnmHeaderModel(self) -> PnmHeaderModel:
        """
        Retrieve the parsed header as a structured Pydantic model.

        Returns
        -------
        PnmHeaderModel
            Structured model representing the parsed header fields.
        """
        return self._pnmheader_model

    def getPnmHeaderParameterModel(self) -> PnmHeaderParameters:
        """
        Retrieve only the parsed parameter model.

        Returns
        -------
        PnmHeaderParameters
            Model containing typed header fields.
        """
        return self._parameters

    def _to_dict(self, header_only: bool = False) -> dict[str, Any]:
        """
        Serialize the header to a Python dictionary.

        Parameters
        ----------
        header_only : bool, optional
            If True, omit binary payload data. Defaults to False.

        Returns
        -------
        Dict[str, Any]
            Dictionary containing the header structure and optionally the payload data.
        """
        out: dict[str, Any] = self.getPnmHeaderModel().model_dump(exclude_none=True)
        if not header_only:
            out["data"] = self.pnm_data.hex()
        return out

    def getPnmHeader(self, header_only: bool = False) -> dict[str, Any]:
        """
        Public getter (maintained for backward compatibility).

        Parameters
        ----------
        header_only : bool, optional
            If True, omit payload data.

        Returns
        -------
        Dict[str, Any]
            Dictionary representation of the header and optional payload.
        """
        return self._to_dict(header_only)

    def get_pnm_file_type(self) -> PnmFileType | None:
        """
        Resolve the parsed PNM file type and version to a known `PnmFileType` enum.

        Returns
        -------
        Optional[PnmFileType]
            Matching enumeration value, or None if unrecognized.
        """
        if self._file_type and self._file_type_num is not None:
            pnm_id: str = (
                f"{self._file_type.decode('utf-8').strip()}{self._file_type_num}"
            )
            for t in PnmFileType:
                if t.value == pnm_id:
                    return t
        return None

    def override_capture_time(self, capture_time: CaptureTime) -> bool:
        """
        Override the capture timestamp when it is missing from the PNM header.

        This method is primarily intended for files that do not embed the
        capture time directly in the header (e.g., FEC Summary `PNN8`).

        Parameters
        ----------
        capture_time : CaptureTime
            Epoch timestamp to assign to the header.

        Returns
        -------
        bool
            True if the capture time was successfully overridden, False otherwise.

        Notes
        -----
        - The header model is automatically rebuilt after a successful override.
        - This method does nothing for standard PNM types that already include
          a capture_time in their binary header.
        """
        self.logger.debug("Attempting to override capture_time to %s", capture_time)

        if not self._file_type or self._file_type_num is None:
            self.logger.warning(
                "Cannot override capture_time: incomplete header fields"
            )
            return False

        pnm_type = f"{self._file_type.decode('utf-8').strip()}{self._file_type_num}"

        if pnm_type in self._MISSING_CAPTURE_TYPES:
            self._capture_time = capture_time
            self.__build_pnm_header_model()
            self.logger.debug(
                "Overrode capture_time=%s for PNM type=%s", capture_time, pnm_type
            )
            return True

        self.logger.debug("No override needed for PNM type=%s", pnm_type)
        return False

    @classmethod
    def from_bytes(cls, data: bytes) -> PnmHeader:
        """
        Create and parse a `PnmHeader` directly from raw bytes.

        Parameters
        ----------
        data : bytes
            Byte sequence starting at the PNM header.

        Returns
        -------
        PnmHeader
            Parsed PNM header instance.
        """
        return cls(data)

    @staticmethod
    def get_model_from_dict(
        data: Mapping[str, Any] | dict[str, Any],
    ) -> PnmHeaderParameters:
        """
                Build a `PnmHeaderParameters` from a known PNM header dictionary.

                This is intended for cases where the original binary header is not
                available and only the structured dictionary (or JSON) form of the
                header exists.

                Parameters
                ----------
                data : Dict[str, Any]
                    Dictionary containing PNM header fields. This may be either:
                    - The full structure produced by `getPnmHeader()` which wraps
                      parameters under the `pnm_header` key, or
                    - A flat mapping of `PnmHeaderParameters` fields.

                Returns
                -------
                PnmHeaderParameters
        .
        """
        header_data = data.get("pnm_header", data)

        return PnmHeaderParameters(**header_data)
