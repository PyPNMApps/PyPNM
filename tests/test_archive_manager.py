# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025

from __future__ import annotations

import io
from pathlib import Path
from typing import Literal, cast

import pytest

from pypnm.lib.archive.manager import ArchiveManager


def write_files(base: Path, files: list[str]) -> None:
    for rel in files:
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"payload:{rel}", encoding="utf-8")


def test_detect_format() -> None:
    assert ArchiveManager.detect_format("a.zip") == "zip"
    assert ArchiveManager.detect_format("a.tgz") == "gztar"
    assert ArchiveManager.detect_format("a.tar.gz") == "gztar"
    assert ArchiveManager.detect_format("a.tbz2") == "bztar"
    assert ArchiveManager.detect_format("a.tar.bz2") == "bztar"
    assert ArchiveManager.detect_format("a.txz") == "xztar"
    assert ArchiveManager.detect_format("a.tar.xz") == "xztar"
    assert ArchiveManager.detect_format("a.tar") == "tar"
    assert ArchiveManager.detect_format("a.unknown") is None


def test_zip_files_write_and_list(tmp_path: Path) -> None:
    src = tmp_path / "src"
    write_files(src, ["a.txt", "dir/b.txt"])

    zip_path = tmp_path / "out.zip"
    ArchiveManager.zip_files([src / "a.txt", src / "dir" / "b.txt"], zip_path, mode="w")

    names = ArchiveManager.list_contents(zip_path, fmt="zip")
    assert set(names) == {"a.txt", "b.txt"}


def test_zip_files_preserve_tree_and_arcname_map(tmp_path: Path) -> None:
    src = tmp_path / "src2"
    write_files(src, ["keep/x.txt", "keep/nested/y.txt"])

    zip_path = tmp_path / "tree.zip"
    ArchiveManager.zip_files(
        [src / "keep" / "x.txt", src / "keep" / "nested" / "y.txt"],
        zip_path,
        preserve_tree=True,
        arcbase=src,
    )
    names = set(ArchiveManager.list_contents(zip_path))
    assert names == {"keep/x.txt", "keep/nested/y.txt"}

    zip_path2 = tmp_path / "map.zip"
    ArchiveManager.zip_files(
        [src / "keep" / "x.txt"],
        zip_path2,
        arcname_map={src / "keep" / "x.txt": "renamed.dat"},
    )
    assert set(ArchiveManager.list_contents(zip_path2)) == {"renamed.dat"}


def test_zip_files_append_and_duplicate_removal(tmp_path: Path) -> None:
    src = tmp_path / "src3"
    write_files(src, ["f1.txt", "f2.txt"])

    zip_path = tmp_path / "append.zip"
    ArchiveManager.zip_files([src / "f1.txt"], zip_path, mode="w")
    ArchiveManager.zip_files(
        [src / "f2.txt", src / "f2.txt"],
        zip_path,
        mode="a",
        remove_duplicate_files=True,
    )
    names = ArchiveManager.list_contents(zip_path)
    assert set(names) == {"f1.txt", "f2.txt"}


@pytest.mark.parametrize("fmt", ["tar", "gztar", "bztar", "xztar"])
def test_tar_files_and_list(tmp_path: Path, fmt: str) -> None:
    src = tmp_path / f"src_{fmt}"
    write_files(src, ["a.txt", "p/q.txt"])

    ext_map = {
        "tar": ".tar",
        "gztar": ".tar.gz",
        "bztar": ".tar.bz2",
        "xztar": ".tar.xz",
    }
    tar_path = tmp_path / f"out_{fmt}{ext_map[fmt]}"

    ArchiveManager.tar_files(
        [src / "a.txt", src / "p" / "q.txt"],
        tar_path,
        fmt=cast(Literal["tar", "gztar", "bztar", "xztar"], fmt),
        preserve_tree=True,
        arcbase=src,
    )
    names = set(ArchiveManager.list_contents(tar_path))
    assert names == {"a.txt", "p/q.txt"}


def test_extract_zip_basic_and_overwrite(tmp_path: Path) -> None:
    src = tmp_path / "src4"
    write_files(src, ["a.txt", "b/c.txt"])

    zpath = tmp_path / "base.zip"
    # Preserve folder structure so we expect "b/c.txt" in extraction results
    ArchiveManager.zip_files(
        [src / "a.txt", src / "b" / "c.txt"],
        zpath,
        mode="w",
        preserve_tree=True,
        arcbase=src,
    )

    out = tmp_path / "out"
    extracted = ArchiveManager.extract(zpath, out)
    assert set(p.relative_to(out).as_posix() for p in extracted) == {"a.txt", "b/c.txt"}

    (out / "a.txt").write_text("changed", encoding="utf-8")
    assert (out / "a.txt").read_text(encoding="utf-8") == "changed"
    # Ensure the rest is still present
    assert (out / "b" / "c.txt").exists()


def test_extract_tar_basic(tmp_path: Path) -> None:
    src = tmp_path / "src5"
    write_files(src, ["x.txt", "d/e.txt"])

    tpath = tmp_path / "base.tar.gz"
    ArchiveManager.tar_files(
        [src / "x.txt", src / "d" / "e.txt"],
        tpath,
        fmt="gztar",
        preserve_tree=True,
        arcbase=src,
    )

    out = tmp_path / "out_tar"
    extracted = ArchiveManager.extract(tpath, out)
    assert set(p.relative_to(out).as_posix() for p in extracted) == {"x.txt", "d/e.txt"}


def test_extract_defends_against_path_traversal_zip(tmp_path: Path) -> None:
    import zipfile

    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../escape.txt", "oops")
        zf.writestr("/abs.txt", "nope")
        zf.writestr("ok/inside.txt", "safe")

    # 1) Full extract should fail because of unsafe members
    with pytest.raises(RuntimeError):
        ArchiveManager.extract(zpath, tmp_path / "unzip")

    # 2) Safe-only extract using members filter should succeed
    out = tmp_path / "unzip_safe"
    extracted = ArchiveManager.extract(
        zpath,
        out,
        members=["ok/inside.txt"],
    )
    assert (out / "ok" / "inside.txt").read_text(encoding="utf-8") == "safe"
    assert {p.relative_to(out).as_posix() for p in extracted} == {"ok/inside.txt"}


def test_extract_defends_against_path_traversal_tar(tmp_path: Path) -> None:
    import tarfile

    tpath = tmp_path / "evil.tar"
    with tarfile.open(tpath, "w") as tf:
        ti = tarfile.TarInfo("safe/file.txt")
        data = b"hello"
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))

        ti2 = tarfile.TarInfo("../../escape.txt")
        ti2.size = 1
        tf.addfile(ti2, io.BytesIO(b"!"))

    # 1) Full extract should fail due to unsafe member
    with pytest.raises(RuntimeError):
        ArchiveManager.extract(tpath, tmp_path / "untar")

    # 2) Safe-only extract using members filter should succeed
    out = tmp_path / "untar_safe"
    extracted = ArchiveManager.extract(
        tpath,
        out,
        members=["safe/file.txt"],
    )
    assert (out / "safe" / "file.txt").read_text(encoding="utf-8") == "hello"
    assert {p.relative_to(out).as_posix() for p in extracted} == {"safe/file.txt"}


def test_list_contents_errors(tmp_path: Path) -> None:
    dummy = tmp_path / "not_an_archive.bin"
    dummy.write_bytes(b"\x00\x01")
    with pytest.raises(ValueError):
        _ = ArchiveManager.list_contents(dummy)
