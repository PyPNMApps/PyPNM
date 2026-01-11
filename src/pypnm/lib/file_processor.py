# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import csv
import json
import logging
import tarfile
import zipfile
from pathlib import Path
from types import TracebackType
from typing import Any, Literal

from pypnm.lib.types import PathLike

DEFAULT_HEXDUMP_BYTES_PER_LINE: int = 16


class FileProcessor:
    def __init__(self, filepath: PathLike) -> None:
        """
        A utility class to handle reading/writing files, hex conversion, and optional archiving.

        Args:
            filepath: Path to the primary file to manage (the file you read/write and can archive).
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.filepath = Path(filepath)
        self.logger.debug(f"Initialized FileProcessor with path: {self.filepath}")

    # ──────────────────────────────────────────────────────────────────────
    # Filesystem basics
    # ──────────────────────────────────────────────────────────────────────
    def file_exists(self) -> bool:
        """Checks if the file exists."""
        return self.filepath.exists()

    def read_file(self) -> bytes:
        """Reads binary data from the file. Returns empty bytes on error."""
        try:
            with open(self.filepath, "rb") as file:
                data = file.read()
                self.logger.debug(f"Read {len(data)} bytes from {self.filepath}")
                return data
        except FileNotFoundError:
            self.logger.error(f"File not found: {self.filepath}")
        except OSError as e:
            self.logger.error(f"Error reading file {self.filepath}: {e}")
        return b""

    def write_file(
        self,
        data: bytes | str | dict,
        *,
        append: bool = False,
        archive_path: PathLike | None = None,
        archive_format: Literal["zip", "gztar", "bztar", "xztar", "tar"] = "zip",
        arcname: str | None = None,
    ) -> bool:
        """
        Writes data to the file. Optionally archives the written file.

        Args:
            data: Data to write (bytes | str | dict). dict is JSON-encoded (utf-8).
            append: If True, appends instead of overwriting (binary for bytes/str/JSON).
            archive_path: If provided, the written file is added/packed into this archive.
            archive_format: 'zip' (appendable) or a tar format for a fresh archive:
                            'gztar' (.tar.gz), 'bztar' (.tar.bz2), 'xztar' (.tar.xz), 'tar' (.tar)
            arcname: Name inside the archive. Defaults to file name.

        Returns:
            True on success (write + optional archive), False otherwise.
        """
        mode = "ab" if append else "wb"
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)

            with open(self.filepath, mode) as file:
                if isinstance(data, str):
                    data_bytes = data.encode("utf-8")
                elif isinstance(data, dict):
                    data_bytes = json.dumps(data, indent=2).encode("utf-8")
                elif isinstance(data, bytes):
                    data_bytes = data
                else:
                    raise ValueError("Unsupported type for file write")

                file.write(data_bytes)
                self.logger.debug(f"Wrote {len(data_bytes)} bytes to {self.filepath}")

            if archive_path:
                self.archive_file(
                    archive_path=archive_path,
                    archive_format=archive_format,
                    arcname=arcname,
                )

            return True
        except Exception as e:
            self.logger.error(f"Failed to write to {self.filepath}: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────
    # CSV
    # ──────────────────────────────────────────────────────────────────────
    def write_csv(
        self,
        data: list[dict[str, Any] | list[Any]],
        headers: list[str] | None = None,
        *,
        append: bool = False,
        filepath: PathLike | None = None,
        archive_path: PathLike | None = None,
        archive_format: Literal["zip", "gztar", "bztar", "xztar", "tar"] = "zip",
        arcname: str | None = None,
    ) -> bool:
        """
        Writes tabular data to a CSV file (dict rows or list rows). Optionally archives it.

        Args:
            data: Rows to write.
            headers: Column headers (required for list rows; ignored for dict rows).
            append: Append rows if True; otherwise overwrite.
            filepath: Path to CSV file. Uses self.filepath if None.
            archive_path: If provided, the CSV is added/packed into this archive.
            archive_format: 'zip' (appendable) or tar formats for a fresh archive.
            arcname: Name inside the archive. Defaults to file name.

        Returns:
            True on success (CSV + optional archive), False otherwise.
        """
        target = Path(filepath) if filepath else self.filepath
        mode = "a" if append else "w"

        try:
            target.parent.mkdir(parents=True, exist_ok=True)

            if not data:
                self.logger.warning("No data provided for CSV write.")
                return False

            with open(target, mode, newline="", encoding="utf-8") as csvfile:
                first = data[0]
                if isinstance(first, dict):
                    fieldnames = list(first.keys())
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    if not append:
                        writer.writeheader()
                    writer.writerows(data)  # type: ignore
                else:
                    writer = csv.writer(csvfile)
                    if headers and not append:
                        writer.writerow(headers)
                    writer.writerows(data)  # type: ignore

            self.logger.debug(f"Wrote {len(data)} rows to CSV at {target}")

            if archive_path:
                self.archive_file(
                    archive_path=archive_path,
                    archive_format=archive_format,
                    arcname=arcname or target.name,
                    file_to_archive=target,
                )

            return True
        except Exception as e:
            self.logger.error(f"Failed to write CSV to {target}: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────
    # Archiving
    # ──────────────────────────────────────────────────────────────────────
    def archive_file(
        self,
        *,
        archive_path: PathLike,
        archive_format: Literal["zip", "gztar", "bztar", "xztar", "tar"] = "zip",
        arcname: str | None = None,
        file_to_archive: PathLike | None = None,
        overwrite: bool = False,
    ) -> Path:
        """
        Add the current file (or a provided file) to an archive.

        - For 'zip': append or create using ZipFile (compression=ZIP_DEFLATED).
        - For tar formats: creates a NEW archive containing only the file (no append).

        Args:
            archive_path: Target archive path. For tar formats, extension should match the format.
            archive_format: 'zip' (appendable) or one of 'gztar'|'bztar'|'xztar'|'tar' (new archive).
            arcname: Name inside the archive (defaults to the file's name).
            file_to_archive: Specific file path; defaults to self.filepath.
            overwrite: If True and creating a new archive (tar formats), remove existing file first.

        Returns:
            Path to the created/updated archive.
        """
        src = Path(file_to_archive) if file_to_archive else self.filepath
        if not src.exists():
            raise FileNotFoundError(f"Cannot archive missing file: {src}")

        archive_path = Path(archive_path)
        arcname = arcname or src.name

        if archive_format == "zip":
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if archive_path.exists() else "w"
            with zipfile.ZipFile(
                archive_path, mode=mode, compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.write(src, arcname=arcname)
            self.logger.debug(f"Added {src} as {arcname} to zip: {archive_path}")
            return archive_path

        if overwrite and archive_path.exists():
            archive_path.unlink(missing_ok=True)

        if archive_format in {"gztar", "bztar", "xztar", "tar"}:
            mode_map = {
                "gztar": "w:gz",
                "bztar": "w:bz2",
                "xztar": "w:xz",
                "tar": "w",
            }
            mode = mode_map[archive_format]
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(archive_path, mode) as tf:  # type: ignore
                tf.add(src, arcname=arcname)
            self.logger.debug(
                f"Created {archive_format} with {src} as {arcname}: {archive_path}"
            )
            return archive_path

        raise ValueError(f"Unsupported archive_format: {archive_format}")

    # ──────────────────────────────────────────────────────────────────────
    # Hex helpers
    # ──────────────────────────────────────────────────────────────────────
    def to_hex(self) -> str:
        """Converts binary file contents to a hex string. Returns empty on failure."""
        data = self.read_file()
        if data:
            hex_data = data.hex()
            self.logger.debug(f"Hex conversion complete: {len(hex_data)} chars")
            return hex_data
        self.logger.warning("No data available to convert to hex.")
        return ""

    def to_binary(self, hex_data: str) -> bytes:
        """Converts a hex string to binary. Returns empty bytes on invalid input."""
        try:
            binary_data = bytes.fromhex(hex_data)
            self.logger.debug(f"Converted hex to binary ({len(binary_data)} bytes)")
            return binary_data
        except ValueError as e:
            self.logger.error(f"Invalid hex data: {e}")
            return b""

    def hexdump(
        self,
        *,
        bytes_per_line: int = DEFAULT_HEXDUMP_BYTES_PER_LINE,
        limit_bytes: int | None = None,
    ) -> list[str]:
        """
        Generate a hexdump view of the file contents as text lines.

        Parameters
        ----------
        bytes_per_line:
            Number of bytes per output line in the hexdump view. Typical values
            are 8, 16, or 32. Non-positive values are coerced to
            DEFAULT_HEXDUMP_BYTES_PER_LINE.
        limit_bytes:
            Optional maximum number of bytes to render from the start of the
            file. If None, the entire file is dumped.

        Returns
        -------
        List[str]
            List of hexdump lines, each including the offset, hex bytes, and
            ASCII representation. Returns an empty list when the file cannot
            be read or is empty.
        """
        if bytes_per_line <= 0:
            bytes_per_line = DEFAULT_HEXDUMP_BYTES_PER_LINE

        data = self.read_file()
        if not data:
            self.logger.warning("No data available for hexdump.")
            return []

        if limit_bytes is not None and limit_bytes > 0:
            data = data[:limit_bytes]

        lines: list[str] = []
        offset: int = 0
        total_len: int = len(data)

        while offset < total_len:
            chunk = data[offset : offset + bytes_per_line]

            hex_bytes = " ".join(f"{b:02x}" for b in chunk)
            ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            padding_size = bytes_per_line - len(chunk)

            if padding_size > 0:
                hex_bytes = f"{hex_bytes}{'   ' * padding_size}"

            line = f"{offset:08x}  {hex_bytes}  |{ascii_repr}|"
            lines.append(line)
            offset += len(chunk)

        return lines

    def print_hex(self, limit: int = 64) -> None:
        """Prints the first N characters of the hex file content."""
        hex_data = self.to_hex()
        if not hex_data:
            self.logger.warning("No hex data to display.")
            snippet = ""
        else:
            snippet = hex_data[:limit]
            self.logger.debug(f"Hex preview: {snippet}")

        print("Hex Preview:", snippet)

    # ──────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────────────────────────────
    def close(self) -> None:
        """Placeholder for any cleanup actions if needed."""
        self.logger.debug("FileProcessor close called, no action taken.")

    def __str__(self) -> str:
        return f"FileProcessor({self.filepath})"

    def __repr__(self) -> str:
        return f"FileProcessor(filepath={self.filepath})"

    def __enter__(self) -> FileProcessor:
        return self

    def __exit__(
        self,
        exc_type: type | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        self.close()
        if exc_type:
            self.logger.error(f"Exception in FileProcessor: {exc_value}")
        else:
            self.logger.debug("FileProcessor exited cleanly.")
        return False
