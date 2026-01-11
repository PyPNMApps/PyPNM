# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

# tests/test_file_processor_hexdump.py

from __future__ import annotations

from pathlib import Path

import pytest

from pypnm.lib.file_processor import DEFAULT_HEXDUMP_BYTES_PER_LINE, FileProcessor


@pytest.mark.pnm
def test_to_hex_and_to_binary_round_trip(tmp_path: Path) -> None:
    """
    Verify that FileProcessor.to_hex and FileProcessor.to_binary are consistent
    for a small binary payload.
    """
    filename = "test_pnm_file.bin"
    payload  = bytes(range(32))  # 0x00..0x1F

    file_path = tmp_path / filename
    file_path.write_bytes(payload)

    fp       = FileProcessor(file_path)
    hex_str  = fp.to_hex()
    restored = fp.to_binary(hex_str)

    assert isinstance(hex_str, str)
    assert len(hex_str) == len(payload) * 2
    assert restored == payload


@pytest.mark.pnm
def test_hexdump_basic_16_bytes_per_line(tmp_path: Path) -> None:
    """
    Exercise FileProcessor.hexdump with bytes_per_line = 16.

    Expect:
      - Exactly 2 lines for a 32-byte payload.
      - First line offset 00000000.
      - Second line offset 00000010.
      - Hex and ASCII columns present.
    """
    filename       = "test_pnm_file.bin"
    bytes_per_line = 16
    payload        = bytes(range(32))

    file_path = tmp_path / filename
    file_path.write_bytes(payload)

    fp: FileProcessor = FileProcessor(file_path)
    lines: list[str]  = fp.hexdump(bytes_per_line=bytes_per_line)

    assert isinstance(lines, list)
    assert len(lines) == 2

    first  = lines[0]
    second = lines[1]

    assert first.startswith("00000000")
    assert "  " in first
    assert "|" in first and first.endswith("|")

    assert second.startswith("00000010")
    assert "|" in second and second.endswith("|")


@pytest.mark.pnm
def test_hexdump_with_custom_bytes_per_line(tmp_path: Path) -> None:
    """
    Verify that hexdump respects the requested bytes_per_line
    and produces the expected number of lines.
    """
    filename       = "test_pnm_file.bin"
    bytes_per_line = 8
    payload        = bytes(range(24))  # 24 bytes -> 3 lines at 8 bytes/line

    file_path = tmp_path / filename
    file_path.write_bytes(payload)

    fp    = FileProcessor(file_path)
    lines = fp.hexdump(bytes_per_line=bytes_per_line)

    assert len(lines) == 3
    assert lines[0].startswith("00000000")
    assert lines[1].startswith("00000008")
    assert lines[2].startswith("00000010")


@pytest.mark.pnm
def test_hexdump_uses_default_when_invalid_bytes_per_line(tmp_path: Path) -> None:
    """
    When bytes_per_line is zero or negative, hexdump should fall back
    to DEFAULT_HEXDUMP_BYTES_PER_LINE and still return a valid dump.
    """
    filename = "test_pnm_file.bin"
    payload  = bytes(range(32))

    file_path = tmp_path / filename
    file_path.write_bytes(payload)

    fp = FileProcessor(file_path)

    lines_zero = fp.hexdump(bytes_per_line=0)
    lines_neg  = fp.hexdump(bytes_per_line=-8)

    # Default is 16, so 32 bytes -> 2 lines
    assert DEFAULT_HEXDUMP_BYTES_PER_LINE == 16
    assert len(lines_zero) == 2
    assert len(lines_neg)  == 2

    assert lines_zero[0].startswith("00000000")
    assert lines_neg[0].startswith("00000000")


@pytest.mark.pnm
def test_hexdump_limit_bytes_truncates_output(tmp_path: Path) -> None:
    """
    limit_bytes must truncate the rendered hexdump to that many bytes,
    independent of the underlying file size.
    """
    filename       = "test_pnm_file.bin"
    bytes_per_line = 16
    payload        = bytes(range(64))  # 64 bytes -> 4 lines at 16 B/line

    file_path = tmp_path / filename
    file_path.write_bytes(payload)

    fp = FileProcessor(file_path)

    # Limit to 16 bytes, expect exactly 1 line
    lines = fp.hexdump(bytes_per_line=bytes_per_line, limit_bytes=16)
    assert len(lines) == 1
    assert lines[0].startswith("00000000")

    # Limit to 20 bytes, expect 2 lines (16 + 4 bytes)
    lines = fp.hexdump(bytes_per_line=bytes_per_line, limit_bytes=20)
    assert len(lines) == 2
    assert lines[0].startswith("00000000")
    assert lines[1].startswith("00000010")


@pytest.mark.pnm
def test_hexdump_empty_file_returns_empty_list(tmp_path: Path) -> None:
    """
    For an empty file, hexdump should return an empty list.
    """
    filename  = "empty.bin"
    file_path = tmp_path / filename
    file_path.write_bytes(b"")

    fp    = FileProcessor(file_path)
    lines = fp.hexdump(bytes_per_line=16)

    assert isinstance(lines, list)
    assert len(lines) == 0
