# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import binascii
import logging
import struct
from pathlib import Path

from pypnm.pnm.parser.pnm_file_type import PnmFileType
from pypnm.pnm.parser.pnm_header import PnmHeader

logger = logging.getLogger(__name__)


def _parse_header_size(byte_array: bytes) -> int:
    """
    Determine header size in bytes based on PNM format.
    """
    special = struct.unpack("<B", byte_array[3:4])[0]
    fmt = "<3sBBB" if special == 8 else "!3sBBBI"
    return struct.calcsize(fmt)


class PnmMacInjector(PnmHeader):
    """
    Extends PnmHeader to allow injecting a MAC address into the binary data.

    Attributes:
        file_path (Path): Path to the PNM file.
        raw_bytes (bytes): Original file content.
        modified_bytes (bytes): Content after MAC injection.
        backup (bool): Whether to backup original file on save.
    """

    HISTOGRAM_OFFSET_DELTA = 0  # No extra offset for histogram type
    DEFAULT_OFFSET_DELTA = 1  # One byte past header for most types

    def __init__(self, file_path: str | Path, backup: bool = True) -> None:
        # Load raw bytes and parse header
        self.file_path = Path(file_path)
        self.raw_bytes = self.file_path.read_bytes()
        super().__init__(self.raw_bytes)
        self.modified_bytes: bytes | None = None
        self.backup = backup
        self.logger = logging.getLogger(self.__class__.__name__)

    def set_mac_address(self, mac: str, offset: int | None = None) -> None:
        """
        Overwrite 6 bytes at given offset in the PNM file with the new MAC address.

        If `offset` is not provided, defaults based on file type:
          - DOWNSTREAM_HISTOGRAM: at end of header (offset = header_size)
          - all others: one byte past header (offset = header_size + 1)

        Args:
            mac (str): MAC in format 'aa:bb:cc:dd:ee:ff'.
            offset (int, optional): Byte offset for injection.

        Raises:
            ValueError: If mac format invalid or file too small.
        """
        # Convert MAC string to 6 bytes
        hexstr = mac.replace(":", "").replace("-", "")
        if len(hexstr) != 12:
            raise ValueError(f"Invalid MAC string: {mac}")
        mac_bytes = binascii.unhexlify(hexstr)

        # Determine default offset if not specified
        if offset is None:
            header_size = _parse_header_size(self.raw_bytes)
            pnm_type = self.get_pnm_file_type()
            if pnm_type == PnmFileType.DOWNSTREAM_HISTOGRAM:
                delta = self.HISTOGRAM_OFFSET_DELTA
            else:
                delta = self.DEFAULT_OFFSET_DELTA
            offset = header_size + delta
            self.logger.debug(
                f"Detected PNM file type: {pnm_type}, header size: {header_size}, using offset: {offset}"
            )

        # Validate file length
        if len(self.raw_bytes) < offset + 6:
            raise ValueError(
                f"File too small ({len(self.raw_bytes)} bytes) for offset {offset}+6"
            )

        # Inject MAC
        self.modified_bytes = (
            self.raw_bytes[:offset] + mac_bytes + self.raw_bytes[offset + 6 :]
        )
        self.logger.debug(f"MAC {mac} injected at offset {offset}")

    def save(self, out_path: str | Path | None = None) -> Path:
        """
        Save the modified bytes back to disk, optionally to a new path.
        Creates a backup of the original if enabled.

        Args:
            out_path (str | Path, optional): Destination file path.

        Returns:
            Path: Path to the written file.
        """
        if self.modified_bytes is None:
            raise RuntimeError("No modifications to save; call set_mac_address first.")

        dest = Path(out_path) if out_path else self.file_path
        if self.backup:
            bak = dest.with_suffix(dest.suffix + ".bak")
            dest.replace(bak)
            self.logger.debug(f"Backup created: {bak}")

        dest.write_bytes(self.modified_bytes)
        self.logger.debug(f"Saved modified file: {dest}")
        return dest
