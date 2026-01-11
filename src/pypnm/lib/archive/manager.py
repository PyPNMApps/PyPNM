# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Maurice Garcia

from __future__ import annotations

import logging
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

from pypnm.lib.types import PathLike

__all__ = ["ArchiveManager"]


CompressionKey = Literal["zipstore", "zipdeflated", "zipbz2", "ziplzma"]
TarFormatKey = Literal["tar", "gztar", "bztar", "xztar"]
ArchiveFormatKey = Literal["zip"] | TarFormatKey
ArchiveMemberName = str
ArchiveMemberIterable = Iterable[ArchiveMemberName]
ZipCompressionMap = dict[CompressionKey, int]
TarModeMap = dict[TarFormatKey, str]


class ArchiveManager:
    """
    Static utilities to archive/extract file collections using Python stdlib.

    Supported formats
    -----------------
    - zip  : appendable (modes "w" or "a"), compression = deflate/bzip2/lzma/store
    - tar  : fresh write each call (modes: tar, gztar=.tar.gz, bztar=.tar.bz2, xztar=.tar.xz)

    Security
    --------
    - extract() defends against path traversal ("../" or absolute paths) by:
      * detecting unsafe members,
      * extracting safe members,
      * directing safe members to either dest_dir or dest_dir + "_safe",
      * logging each unsafe member,
      * and raising RuntimeError if any unsafe member was encountered.
    """

    _ZIP_COMP: ZipCompressionMap = {
        "zipstore": zipfile.ZIP_STORED,
        "zipdeflated": zipfile.ZIP_DEFLATED,
        "zipbz2": zipfile.ZIP_BZIP2,
        "ziplzma": zipfile.ZIP_LZMA,
    }

    _TAR_MODE: TarModeMap = {
        "tar": "w",
        "gztar": "w:gz",
        "bztar": "w:bz2",
        "xztar": "w:xz",
    }

    _LOG = logging.getLogger("ArchiveManager")

    # ──────────────────────────────────────────────────────────────────────────
    # Detection / Listing
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def detect_format(archive_path: PathLike) -> str | None:
        """
        Guess format from file suffix.

        Returns
        -------
        Optional[str]
            One of "zip", "tar", "gztar", "bztar", "xztar", or None if the
            suffix does not look like a supported archive type.
        """
        p = Path(archive_path)
        suf = "".join(p.suffixes).lower()
        if suf.endswith(".zip"):
            return "zip"
        if suf.endswith(".tar.gz") or suf.endswith(".tgz"):
            return "gztar"
        if suf.endswith(".tar.bz2") or suf.endswith(".tbz2"):
            return "bztar"
        if suf.endswith(".tar.xz") or suf.endswith(".txz"):
            return "xztar"
        if suf.endswith(".tar"):
            return "tar"
        return None

    @staticmethod
    def list_contents(archive_path: PathLike, fmt: str | None = None) -> list[str]:
        """
        Return member names in the archive.

        Parameters
        ----------
        archive_path : PathLike
            Path to the archive on disk.
        fmt : Optional[str]
            Optional explicit format ("zip", "tar", "gztar", "bztar", "xztar").
            When omitted, the format is derived from the filename suffix.

        Returns
        -------
        List[str]
            Raw member names as stored in the archive.
        """
        fmt = fmt or ArchiveManager.detect_format(archive_path)
        if fmt == "zip":
            with zipfile.ZipFile(archive_path, "r") as zf:
                return zf.namelist()
        elif fmt in ArchiveManager._TAR_MODE:
            with tarfile.open(archive_path, "r:*") as tf:
                return [m.name for m in tf.getmembers()]
        raise ValueError(
            f"Unsupported or undetected archive format for: {archive_path}"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Create archives
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def zip_files(
        files: Iterable[PathLike],
        archive_path: PathLike,
        *,
        mode: Literal["w", "a"] = "w",
        compression: CompressionKey = "zipdeflated",
        arcbase: PathLike | None = None,
        preserve_tree: bool = False,
        arcname_map: dict[PathLike, str] | None = None,
        skip_missing: bool = True,
        remove_duplicate_files: bool = True,
    ) -> Path:
        """
        Write (or append) files to a ZIP archive.

        Parameters
        ----------
        files : Iterable[PathLike]
            Collection of paths to add to the archive.
        archive_path : PathLike
            Target ZIP file path.
        mode : {"w", "a"}, default "w"
            Creation mode, "w" to create a new archive, "a" to append.
        compression : CompressionKey, default "zipdeflated"
            Compression strategy for the ZIP file.
        arcbase : Optional[PathLike]
            Base directory used when preserve_tree=True to compute relative
            paths in the archive.
        preserve_tree : bool, default False
            When True, keep directory structure relative to arcbase.
        arcname_map : Optional[Dict[PathLike, str]]
            Optional explicit mapping from source path to archive name.
        skip_missing : bool, default True
            When True, missing files are logged and skipped; when False a
            FileNotFoundError is raised.
        remove_duplicate_files : bool, default True
            When True, duplicate real paths are de-duplicated before archiving.

        Returns
        -------
        Path
            Path to the created/updated ZIP archive.
        """
        comp = ArchiveManager._ZIP_COMP[compression]
        ap = Path(archive_path)
        ap.parent.mkdir(parents=True, exist_ok=True)

        if remove_duplicate_files:
            files = ArchiveManager.__remove_duplicates(files)

        with zipfile.ZipFile(ap, mode=mode, compression=comp) as zf:
            for f in files:
                src = Path(f)
                if not src.exists():
                    if skip_missing:
                        ArchiveManager._LOG.warning(
                            "zip_files: missing: %s (skipped)", src
                        )
                        continue
                    raise FileNotFoundError(src)

                if arcname_map and f in arcname_map:
                    arcname = arcname_map[f]
                elif preserve_tree and arcbase is not None:
                    try:
                        arcname = str(
                            src.resolve().relative_to(Path(arcbase).resolve())
                        )
                    except Exception:
                        arcname = src.name
                else:
                    arcname = src.name

                logging.debug("Archiving: %s to %s", f, arcname)
                zf.write(src, arcname)
        return ap

    @staticmethod
    def tar_files(
        files: Iterable[PathLike],
        archive_path: PathLike,
        *,
        fmt: TarFormatKey = "gztar",
        arcbase: PathLike | None = None,
        preserve_tree: bool = False,
        arcname_map: dict[PathLike, str] | None = None,
        skip_missing: bool = True,
        overwrite: bool = True,
    ) -> Path:
        """
        Create a new tar-based archive (no append for compressed tars).

        Parameters
        ----------
        files : Iterable[PathLike]
            Collection of paths to add to the archive.
        archive_path : PathLike
            Target tar file path.
        fmt : TarFormatKey, default "gztar"
            Tar format/compression ("tar", "gztar", "bztar", "xztar").
        arcbase : Optional[PathLike]
            Base directory used when preserve_tree=True to compute relative
            paths in the archive.
        preserve_tree : bool, default False
            When True, keep directory structure relative to arcbase.
        arcname_map : Optional[Dict[PathLike, str]]
            Optional explicit mapping from source path to archive name.
        skip_missing : bool, default True
            When True, missing files are logged and skipped; when False a
            FileNotFoundError is raised.
        overwrite : bool, default True
            When True, an existing archive at archive_path is removed first.

        Returns
        -------
        Path
            Path to the created tar archive.
        """
        mode = ArchiveManager._TAR_MODE[fmt]
        ap = Path(archive_path)
        ap.parent.mkdir(parents=True, exist_ok=True)
        if overwrite and ap.exists():
            ap.unlink(missing_ok=True)

        with tarfile.open(ap, mode) as tf:  # pyright: ignore[reportArgumentType, reportCallIssue]
            for f in files:
                src = Path(f)
                if not src.exists():
                    if skip_missing:
                        ArchiveManager._LOG.warning(
                            "tar_files: missing: %s (skipped)", src
                        )
                        continue
                    raise FileNotFoundError(src)

                if arcname_map and f in arcname_map:
                    arcname = arcname_map[f]  # type: ignore[index]
                elif preserve_tree and arcbase is not None:
                    try:
                        arcname = str(
                            src.resolve().relative_to(Path(arcbase).resolve())
                        )
                    except Exception:
                        arcname = src.name
                else:
                    arcname = src.name

                tf.add(src, arcname=arcname)
        return ap

    # ──────────────────────────────────────────────────────────────────────────
    # Internal path-traversal helper
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _is_unsafe_name(name: ArchiveMemberName) -> bool:
        """
        Basic path-traversal detection based on name components.

        Rules
        -----
        - Leading '/' or '\\' => unsafe (absolute path).
        - Any '..' path component => unsafe.
        """
        norm = name.replace("\\", "/")
        if norm.startswith("/"):
            return True
        parts = [p for p in norm.split("/") if p not in ("", ".")]
        return any(p == ".." for p in parts)

    # ──────────────────────────────────────────────────────────────────────────
    # Extraction
    # ──────────────────────────────────────────────────────────────────────────
    @staticmethod
    def extract(
        archive_path: PathLike,
        dest_dir: PathLike,
        *,
        fmt: ArchiveFormatKey | None = None,
        members: ArchiveMemberIterable | None = None,
        overwrite: bool = True,
    ) -> list[Path]:
        """
        Extract Archive Contents Into A Target Directory With Path Traversal Protection.

        This helper unpacks ZIP or tar-family archives while defending against
        directory traversal attempts (e.g., members named "../evil" or absolute
        paths like "/tmp/evil"). Unsafe entries are skipped, logged, and will
        cause the call to raise RuntimeError after extraction.

        Parameters
        ----------
        archive_path : PathLike
            Existing archive on disk (ZIP or tar-family).
        dest_dir : PathLike
            Base output directory. When all members are safe, extracted files
            are written under this directory. When any unsafe member is
            detected, all *safe* members are instead written under a sibling
            directory named "<dest_dir>_safe".
        fmt : Optional[ArchiveFormatKey], default None
            Explicit archive format ("zip", "tar", "gztar", "bztar", "xztar").
            When omitted, the format is derived from the archive filename
            suffix via detect_format().
        members : Optional[ArchiveMemberIterable], default None
            Optional whitelist of archive member names to extract. When None,
            every member in the archive is inspected and considered for
            extraction.
        overwrite : bool, default True
            When True, existing files at the resolved output paths are
            overwritten. When False, existing files are left untouched and
            skipped.

        Returns
        -------
        List[Path]
            Concrete filesystem paths for all extracted *files* (directories
            created along the way are not included in this list).

        Raises
        ------
        RuntimeError
            If at least one unsafe member name is detected (absolute paths or
            any component equal to '..'). Safe members will still be extracted
            into the "*_safe" directory before the exception is raised.
        ValueError
            If the archive format is unsupported or cannot be detected from
            the filename when fmt is not provided.
        FileNotFoundError
            If archive_path does not exist.
        """
        ap = Path(archive_path)
        dest = Path(dest_dir)
        fmt = fmt or ArchiveManager.detect_format(ap)  # pyright: ignore[reportAssignmentType]

        if fmt is None:
            raise ValueError(
                f"Unsupported or undetected archive format for: {archive_path}"
            )

        extracted: list[Path] = []

        # ── ZIP ───────────────────────────────────────────────────────────────
        if fmt == "zip":
            with zipfile.ZipFile(ap, "r") as zf:
                all_names = list(members) if members is not None else zf.namelist()

                unsafe_present = any(
                    ArchiveManager._is_unsafe_name(n) for n in all_names
                )
                base_dir = dest.parent / f"{dest.name}_safe" if unsafe_present else dest

                base_dir.mkdir(parents=True, exist_ok=True)

                for name in all_names:
                    if ArchiveManager._is_unsafe_name(name):
                        ArchiveManager._LOG.warning(
                            "extract: skipping unsafe zip member: %s", name
                        )
                        continue

                    tgt = base_dir / name
                    if tgt.exists() and not overwrite:
                        continue

                    if name.endswith("/"):
                        tgt.mkdir(parents=True, exist_ok=True)
                        continue

                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(name) as src, open(tgt, "wb") as dst:
                        dst.write(src.read())
                    extracted.append(tgt)

            if unsafe_present:
                raise RuntimeError(f"Unsafe path(s) detected in zip archive: {ap}")

            return extracted

        # ── TAR ───────────────────────────────────────────────────────────────
        if fmt in ArchiveManager._TAR_MODE:
            with tarfile.open(ap, "r:*") as tf:
                all_members = tf.getmembers()
                if members is not None:
                    wanted = set(members)
                    sel = [m for m in all_members if m.name in wanted]
                else:
                    sel = all_members

                unsafe_present = any(
                    ArchiveManager._is_unsafe_name(m.name) for m in sel
                )
                base_dir = dest.parent / f"{dest.name}_safe" if unsafe_present else dest

                base_dir.mkdir(parents=True, exist_ok=True)

                for m in sel:
                    if ArchiveManager._is_unsafe_name(m.name):
                        ArchiveManager._LOG.warning(
                            "extract: skipping unsafe tar member: %s", m.name
                        )
                        continue

                    tgt = base_dir / m.name
                    if m.isdir():
                        tgt.mkdir(parents=True, exist_ok=True)
                        continue

                    if tgt.exists() and not overwrite:
                        continue

                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    src_file = tf.extractfile(m)
                    if src_file is None:
                        continue
                    with src_file as src, open(tgt, "wb") as dst:
                        dst.write(src.read())
                    extracted.append(tgt)

            if unsafe_present:
                raise RuntimeError(f"Unsafe path(s) detected in tar archive: {ap}")

            return extracted

        raise ValueError(
            f"Unsupported or undetected archive format for: {archive_path}"
        )

    @staticmethod
    def __remove_duplicates(files: Iterable[PathLike]) -> list[Path]:
        """Ensure each path exists and appears only once (order preserved)."""
        seen: set[Path] = set()
        out: list[Path] = []
        for f in files:
            p = Path(f)
            if not p.exists():
                raise FileNotFoundError(p)
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                out.append(rp)
        return out
