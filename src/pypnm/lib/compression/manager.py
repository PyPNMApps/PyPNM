# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import gzip
import logging
import shutil
from pathlib import Path

from pypnm.lib.system_call.manager import SystemCall


class CompressionManager:
    """
    Provide gzip and zstd compression/decompression helpers.
    """

    def __init__(self, system_call: SystemCall | None = None) -> None:
        self.logger = logging.getLogger(f"{self.__class__.__name__}")
        self._system_call = system_call or SystemCall()

    def select_codec(self, primary: str, gzip_fallback: bool) -> str | None:
        if primary == "zstd":
            if self._is_zstd_available():
                return "zst"
            if gzip_fallback:
                return "gz"
            return None
        if primary == "gzip":
            return "gz"
        return None

    def compress(self, codec: str, src: Path, dest: Path, level: int) -> None:
        if codec == "zst":
            self._compress_zstd(src, dest, level)
            return
        if codec == "gz":
            self._compress_gzip(src, dest, level)
            return
        raise ValueError(f"Unsupported compression codec: {codec}")

    def decompress(self, codec: str, src: Path, dest: Path) -> None:
        if codec == "zst":
            self._decompress_zstd(src, dest)
            return
        if codec == "gz":
            self._decompress_gzip(src, dest)
            return
        raise ValueError(f"Unsupported compression codec: {codec}")

    @staticmethod
    def _is_zstd_available() -> bool:
        return shutil.which("zstd") is not None

    def _compress_zstd(self, src: Path, dest: Path, level: int) -> None:
        cmd = ["zstd", f"-{level}", "-q", "-f", "-o", str(dest), str(src)]
        self._system_call.run(cmd, check=True)

    @staticmethod
    def _compress_gzip(src: Path, dest: Path, level: int) -> None:
        with src.open("rb") as f_in, gzip.open(dest, "wb", compresslevel=level) as f_out:
            f_out.writelines(f_in)

    def _decompress_zstd(self, src: Path, dest: Path) -> None:
        cmd = ["zstd", "-d", "-q", "-f", "-o", str(dest), str(src)]
        self._system_call.run(cmd, check=True)

    @staticmethod
    def _decompress_gzip(src: Path, dest: Path) -> None:
        with gzip.open(src, "rb") as f_in, dest.open("wb") as f_out:
            f_out.writelines(f_in)
