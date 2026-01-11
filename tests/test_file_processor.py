# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import json
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from pypnm.lib.file_processor import FileProcessor


def test_file_exists_and_read_write_bytes(tmp_path: Path) -> None:
    p = tmp_path / "bin.dat"
    fp = FileProcessor(p)
    assert fp.file_exists() is False

    data = b"\x01\x02\x03"
    ok = fp.write_file(data)
    assert ok is True
    assert fp.file_exists() is True
    assert fp.read_file() == data

    # append
    ok2 = fp.write_file(b"\x04", append=True)
    assert ok2 is True
    assert fp.read_file() == b"\x01\x02\x03\x04"


def test_write_file_str_and_json(tmp_path: Path) -> None:
    p = tmp_path / "text.json"
    fp = FileProcessor(p)

    assert fp.write_file("hello") is True
    assert p.read_text(encoding="utf-8") == "hello"

    payload: dict[str, Any] = {"a": 1, "b": "x"}
    assert fp.write_file(payload) is True
    # second write overwrote file (append=False default)
    obj = json.loads(p.read_text(encoding="utf-8"))
    assert obj == payload


def test_read_file_missing_returns_empty(tmp_path: Path) -> None:
    p = tmp_path / "nope.bin"
    fp = FileProcessor(p)
    assert fp.read_file() == b""


def test_to_hex_and_to_binary_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "hex.bin"
    fp = FileProcessor(p)
    raw = bytes(range(16))
    assert fp.write_file(raw) is True

    hx = fp.to_hex()
    assert isinstance(hx, str) and len(hx) == 32  # 16 bytes -> 32 hex chars
    assert fp.to_binary(hx) == raw

    # bad hex returns empty
    assert fp.to_binary("zzz") == b""


def test_print_hex_captures_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    p = tmp_path / "h.bin"
    fp = FileProcessor(p)
    fp.write_file(b"\xAA\xBB\xCC\xDD")
    fp.print_hex(limit=4)
    out = capsys.readouterr().out
    assert "Hex Preview:" in out


def test_write_csv_with_dict_rows_and_archive_zip(tmp_path: Path) -> None:
    csv_path = tmp_path / "out.csv"
    arc_path = tmp_path / "out.zip"
    fp = FileProcessor(csv_path)

    rows: list[dict[str, Any]] = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]
    ok = fp.write_csv(rows, archive_path=arc_path, archive_format="zip")
    assert ok is True
    assert csv_path.exists() is True and arc_path.exists() is True

    with zipfile.ZipFile(arc_path, "r") as zf:
        names = set(zf.namelist())
        assert csv_path.name in names
        body = zf.read(csv_path.name).decode("utf-8").strip().splitlines()
        assert body[0] == "a,b"
        assert body[1] == "1,2"


def test_write_csv_with_list_rows_and_headers_and_append(tmp_path: Path) -> None:
    csv_path = tmp_path / "rows.csv"
    fp = FileProcessor(csv_path)

    rows1: list[list[Any]] = [[1, 2], [3, 4]]
    assert fp.write_csv(rows1, headers=["x", "y"]) is True
    rows2: list[list[Any]] = [[5, 6]]
    assert fp.write_csv(rows2, headers=["ignored", "ignored"], append=True) is True

    text = csv_path.read_text(encoding="utf-8").strip().splitlines()
    assert text[0] == "x,y"  # header once
    assert text[-1] == "5,6"  # appended row


@pytest.mark.parametrize("fmt,ext", [("tar", ".tar"), ("gztar", ".tar.gz"), ("bztar", ".tar.bz2"), ("xztar", ".tar.xz")])
def test_archive_file_tar_formats(tmp_path: Path, fmt: str, ext: str) -> None:
    src = tmp_path / "payload.txt"
    src.write_text("hello", encoding="utf-8")
    arc = tmp_path / f"bundle{ext}"

    fp = FileProcessor(src)
    out = fp.archive_file(archive_path=arc, archive_format=fmt, arcname="inside.txt", overwrite=True)
    assert out == arc and arc.exists() is True

    # Inspect tar-like with tarfile open auto-detect
    with tarfile.open(arc, "r:*") as tf:
        names = [m.name for m in tf.getmembers()]
        assert "inside.txt" in names
        content = tf.extractfile("inside.txt")
        assert content is not None and content.read().decode("utf-8") == "hello"


def test_archive_file_zip_append(tmp_path: Path) -> None:
    src1 = tmp_path / "a.txt"
    src2 = tmp_path / "b.txt"
    src1.write_text("A", encoding="utf-8")
    src2.write_text("B", encoding="utf-8")
    arc = tmp_path / "mix.zip"

    fp1 = FileProcessor(src1)
    out1 = fp1.archive_file(archive_path=arc, archive_format="zip", arcname="first.txt")
    assert out1 == arc and arc.exists()

    fp2 = FileProcessor(src2)
    out2 = fp2.archive_file(archive_path=arc, archive_format="zip", arcname="second.txt")
    assert out2 == arc

    with zipfile.ZipFile(arc, "r") as zf:
        names = set(zf.namelist())
        assert names == {"first.txt", "second.txt"}
        assert zf.read("first.txt").decode() == "A"
        assert zf.read("second.txt").decode() == "B"


def test_write_csv_no_data_returns_false(tmp_path: Path) -> None:
    p = tmp_path / "empty.csv"
    fp = FileProcessor(p)
    assert fp.write_csv([], headers=["a", "b"]) is False
    assert p.exists() is False


def test_context_manager_and_repr(tmp_path: Path) -> None:
    p = tmp_path / "ctx.bin"
    with FileProcessor(p) as fp:
        assert "FileProcessor(" in str(fp)
        assert "FileProcessor(filepath=" in repr(fp)
        assert fp.write_file(b"x") is True
    # on exit, nothing thrown
    assert p.read_bytes() == b"x"


def test_write_file_archives_with_custom_arcname(tmp_path: Path) -> None:
    p = tmp_path / "note.txt"
    z = tmp_path / "pkg.zip"
    fp = FileProcessor(p)
    assert fp.write_file("data", archive_path=z, archive_format="zip", arcname="renamed.txt") is True

    with zipfile.ZipFile(z, "r") as zf:
        assert "renamed.txt" in zf.namelist()
        assert zf.read("renamed.txt").decode("utf-8") == "data"
