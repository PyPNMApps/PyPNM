# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from pypnm.api.routes.common.classes.file_capture.types import CompressionMetadataModel
from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig
from pypnm.lib.compression.manager import CompressionManager
from pypnm.lib.system_call.manager import SystemCall
from pypnm.lib.types import FileNameStr, PathLike, TransactionId


@dataclass(frozen=True)
class ArtifactCommitResult:
    stored_filename: FileNameStr
    stored_path: Path
    compression: dict[str, object] | None
    size_before: int
    size_after: int


class PnmArtifactStore:
    """
    Manage at-rest compression and materialized caches for PNM artifacts.
    """

    _STAMP_SUFFIX = ".stamp.json"

    def __init__(self, config: PnmArtifactStorageConfig | None = None, pnm_dir: PathLike | None = None) -> None:
        """
        Initialize artifact storage with compression and cache configuration.

        Parameters
        ----------
        config:
            Optional explicit artifact storage configuration. When omitted,
            the config is loaded from the system configuration.
        pnm_dir:
            Optional override for the durable PNM storage root.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self._config = config or self._load_config()
        self._pnm_dir = Path(pnm_dir) if pnm_dir is not None else Path(self._load_pnm_dir())
        self._compression_manager = CompressionManager(SystemCall())
        self._tmp_root = Path(self._config.cache.tmp_root)
        self._ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        self._materialized_dir = self._tmp_root / self._config.cache.materialized_dir
        self._last_cleanup = 0.0

        self._pnm_dir.mkdir(parents=True, exist_ok=True)
        self._tmp_root.mkdir(parents=True, exist_ok=True)
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        self._materialized_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_tmp_pypnm_permissions()

    def ingress_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return a writable ingress path for a capture file.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID (ignored; ingress is a flat directory).

        Returns
        -------
        Path
            Filesystem path where callers can write the ingress artifact.
        """
        self._tmp_root.mkdir(parents=True, exist_ok=True)
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_tmp_pypnm_permissions()
        return self._ingress_dir / self._normalize_ingress_name(filename)

    def ingress_candidate_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return the expected ingress path without creating directories.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID (ignored; ingress is a flat directory).

        Returns
        -------
        Path
            Expected ingress location for the artifact.
        """
        return self._ingress_dir / self._normalize_ingress_name(filename)

    def find_ingress_by_filename(self, filename: FileNameStr) -> Path | None:
        """
        Search ingress cache for a filename, returning a unique match.

        Parameters
        ----------
        filename:
            Filename to search for (normalized to raw filename).

        Returns
        -------
        Path | None
            Matching ingress path when exactly one file is found; otherwise None.
        """
        target = self._normalize_ingress_name(filename)
        matches = list(self._ingress_dir.glob(target))
        if len(matches) == 1:
            return matches[0]
        return None

    def _ensure_tmp_pypnm_permissions(self) -> None:
        """Ensure /tmp/pypnm and all descendants are world-writable for shared cache usage."""
        expected = Path("/tmp/pypnm")
        try:
            if self._tmp_root.resolve() != expected.resolve():
                return
        except OSError:
            if self._tmp_root != expected:
                return

        uid = os.getuid()
        for path in [self._tmp_root, *self._tmp_root.rglob("*")]:
            self._chmod_world_writable_if_owned(path, uid)

    def _chmod_world_writable_if_owned(self, path: Path, uid: int) -> None:
        """Set path mode to 0777 when owned by the current process user."""
        try:
            if path.stat().st_uid != uid:
                return
            os.chmod(path, 0o777)
        except PermissionError:
            return
        except OSError as exc:
            self.logger.warning("Unable to set permissions 0777 on %s: %s", path, exc)

    @staticmethod
    def _normalize_ingress_name(filename: FileNameStr) -> str:
        name = Path(str(filename)).name
        if name.endswith(".zst"):
            return name[:-4]
        if name.endswith(".gz"):
            return name[:-3]
        return name

    def commit_ingress_file(
        self,
        pnm_type: str,
        ingress_path: Path,
        original_filename: FileNameStr,
    ) -> ArtifactCommitResult:
        """
        Commit an ingress file into the durable store with compression policy.

        Parameters
        ----------
        pnm_type:
            PNM type string used to evaluate compression policy.
        ingress_path:
            Filesystem path of the ingress artifact to commit.
        original_filename:
            Original filename used to derive the stored filename.

        Returns
        -------
        ArtifactCommitResult
            Commit metadata including stored filename, sizes, and compression info.
        """
        self._maybe_cleanup()

        if not ingress_path.is_file():
            raise FileNotFoundError(f"Ingress file not found: {ingress_path}")

        size_before = ingress_path.stat().st_size
        if not self._config.compression.enabled:
            return self._commit_raw(ingress_path, original_filename, size_before)

        if size_before < self._config.compression.min_bytes:
            return self._commit_raw(ingress_path, original_filename, size_before)

        policy = self._config.compression
        action = self._compression_action(pnm_type)

        if action == "deny":
            return self._commit_raw(ingress_path, original_filename, size_before)

        codec = self._compression_manager.select_codec(policy.primary_codec, policy.gzip_fallback)
        if codec is None:
            return self._commit_raw(ingress_path, original_filename, size_before)

        compressed_path = self._pnm_dir / f"{Path(str(original_filename)).name}.{codec}"
        tmp_path = self._pnm_dir / f".{compressed_path.name}.tmp"

        level = policy.zstd_level if codec == "zst" else policy.gzip_level
        self._compression_manager.compress(codec, ingress_path, tmp_path, level)

        size_after = tmp_path.stat().st_size
        ratio = size_after / size_before if size_before else 1.0
        savings = size_before - size_after

        if (
            action == "conditional"
            and ratio > policy.conditional_max_ratio
            and savings < policy.conditional_min_savings_bytes
        ):
            tmp_path.unlink(missing_ok=True)
            return self._commit_raw(ingress_path, original_filename, size_before)

        os.replace(tmp_path, compressed_path)

        compression = CompressionMetadataModel(
            is_compressed=True,
            codec="zstd" if codec == "zst" else "gzip",
            level=policy.zstd_level if codec == "zst" else policy.gzip_level,
            size_before=size_before,
            size_after=size_after,
        )
        return ArtifactCommitResult(
            stored_filename=FileNameStr(compressed_path.name),
            stored_path=compressed_path,
            compression=compression.model_dump(),
            size_before=size_before,
            size_after=size_after,
        )

    def resolve_physical_path(self, filename: FileNameStr, compression: dict[str, object] | None) -> Path:
        """
        Resolve the on-disk artifact path using filename and compression metadata.

        Parameters
        ----------
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        Path
            Best-effort resolved physical path on disk.
        """
        base = Path(str(filename)).name
        if compression and compression.get("is_compressed") is True:
            codec = self._codec_from_filename(base, compression)
            if codec == "zst":
                name = base if base.endswith(".zst") else f"{base}.zst"
                candidate = self._pnm_dir / name
                if candidate.is_file():
                    return candidate
            if codec == "gz":
                name = base if base.endswith(".gz") else f"{base}.gz"
                candidate = self._pnm_dir / name
                if candidate.is_file():
                    return candidate
            candidate = self._pnm_dir / base
            if candidate.is_file():
                return candidate

        raw_path = self._pnm_dir / base
        if raw_path.is_file():
            return raw_path

        zstd_path = self._pnm_dir / f"{base}.zst"
        if zstd_path.is_file():
            return zstd_path

        gzip_path = self._pnm_dir / f"{base}.gz"
        if gzip_path.is_file():
            return gzip_path

        return raw_path

    def materialize(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> Path:
        """
        Provide a raw file path, materializing compressed artifacts into cache.

        Parameters
        ----------
        transaction_id:
            Transaction identifier for scoping the materialized cache path.
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        Path
            Path to a raw artifact, either the durable store or materialized cache.
        """
        self._maybe_cleanup()

        physical_path = self.resolve_physical_path(filename, compression)
        codec = self._codec_from_filename(physical_path.name, compression)
        if codec is None:
            return physical_path

        materialized_path = self._materialized_path(transaction_id, physical_path)
        stamp_path = Path(f"{materialized_path}{self._STAMP_SUFFIX}")

        if self._stamp_valid(stamp_path, physical_path, codec, materialized_path):
            return materialized_path

        self.logger.warning(
            "Uncompressed cache miss for transaction %s; raw file not cached, decompressing %s",
            transaction_id,
            physical_path,
        )
        materialized_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = materialized_path.with_name(f".{materialized_path.name}.tmp")

        self._compression_manager.decompress(codec, physical_path, tmp_path)

        os.replace(tmp_path, materialized_path)
        self._write_stamp(stamp_path, physical_path, codec)
        return materialized_path

    def read_bytes(
        self,
        transaction_id: TransactionId,
        filename: FileNameStr,
        compression: dict[str, object] | None,
    ) -> bytes:
        """
        Read artifact bytes, materializing into cache as needed.

        Parameters
        ----------
        transaction_id:
            Transaction identifier for cache scoping.
        filename:
            Stored filename as recorded in the transaction record.
        compression:
            Compression metadata dict, when available.

        Returns
        -------
        bytes
            Raw artifact bytes.
        """
        materialized = self.materialize(transaction_id, filename, compression)
        return materialized.read_bytes()

    def _load_config(self) -> PnmArtifactStorageConfig:
        """
        Load artifact storage configuration from system config.
        """
        config = ConfigManager().get("PnmArtifactStorage")
        return PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)

    def _load_pnm_dir(self) -> PathLike:
        """
        Load the configured PNM storage directory.
        """
        config = ConfigManager().get("PnmFileRetrieval", "pnm_dir")
        if isinstance(config, str) and config.strip():
            return config
        return ".data/pnm"

    def _compression_action(self, pnm_type: str) -> str:
        """
        Resolve the compression policy action for a PNM type.
        """
        policy = self._config.compression
        if pnm_type in policy.deny:
            return "deny"
        if pnm_type in policy.always:
            return "always"
        if pnm_type in policy.conditional:
            return "conditional"
        return "deny"

    @staticmethod
    def _raw_compression_metadata(size: int) -> CompressionMetadataModel:
        """
        Build compression metadata for uncompressed artifacts.
        """
        return CompressionMetadataModel(
            is_compressed=False,
            codec="none",
            level=0,
            size_before=size,
            size_after=size,
        )

    def _commit_raw(
        self,
        ingress_path: Path,
        original_filename: FileNameStr,
        size_before: int,
    ) -> ArtifactCommitResult:
        """
        Persist an uncompressed artifact into the durable store.
        """
        dest_path = self._pnm_dir / Path(str(original_filename)).name
        tmp_path = self._pnm_dir / f".{dest_path.name}.tmp"
        shutil.copy2(ingress_path, tmp_path)
        os.replace(tmp_path, dest_path)
        compression = self._raw_compression_metadata(size_before)
        return ArtifactCommitResult(
            stored_filename=FileNameStr(dest_path.name),
            stored_path=dest_path,
            compression=compression.model_dump(),
            size_before=size_before,
            size_after=size_before,
        )

    def _codec_from_filename(self, filename: str, compression: dict[str, object] | None) -> str | None:
        """
        Detect codec from metadata and filename extension.
        """
        if compression and compression.get("is_compressed") is True:
            codec = compression.get("codec")
            if isinstance(codec, str):
                if filename.endswith(".zst") and codec != "zstd":
                    self.logger.warning("Compression metadata codec '%s' conflicts with .zst extension", codec)
                if filename.endswith(".gz") and codec != "gzip":
                    self.logger.warning("Compression metadata codec '%s' conflicts with .gz extension", codec)
                return "zst" if codec == "zstd" else "gz" if codec == "gzip" else None
        if filename.endswith(".zst"):
            return "zst"
        if filename.endswith(".gz"):
            return "gz"
        return None

    def _is_compressed(self, compression: dict[str, object] | None, filename: str) -> bool:
        """
        Determine whether a file is compressed based on metadata or extension.
        """
        if compression and compression.get("is_compressed") is True:
            return True
        return filename.endswith(".zst") or filename.endswith(".gz")

    def _materialized_path(self, transaction_id: TransactionId, source_path: Path) -> Path:
        """
        Build the cache path for a materialized artifact copy.
        """
        name = source_path.name
        if name.endswith(".zst"):
            name = name[:-4]
        elif name.endswith(".gz"):
            name = name[:-3]
        return self._materialized_dir / str(transaction_id) / name

    def _write_stamp(self, stamp_path: Path, source_path: Path, codec: str) -> None:
        """
        Write a cache stamp describing the source artifact.
        """
        payload = {
            "source_path": str(source_path),
            "source_mtime": source_path.stat().st_mtime,
            "source_size": source_path.stat().st_size,
            "codec": codec,
        }
        stamp_path.write_text(json.dumps(payload))

    def _stamp_valid(self, stamp_path: Path, source_path: Path, codec: str, materialized_path: Path) -> bool:
        """
        Validate a materialized cache stamp against the source artifact.
        """
        if not stamp_path.is_file() or not materialized_path.is_file():
            return False
        try:
            data = json.loads(stamp_path.read_text())
        except Exception:
            return False
        if data.get("source_path") != str(source_path):
            return False
        if data.get("source_mtime") != source_path.stat().st_mtime:
            return False
        if data.get("source_size") != source_path.stat().st_size:
            return False
        return data.get("codec") == codec

    def _maybe_cleanup(self) -> None:
        """
        Run cache cleanup on a configured cadence.
        """
        now = time.time()
        interval = self._config.cache.cleanup_interval_seconds
        if now - self._last_cleanup < interval:
            return
        self._cleanup_dir(self._ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(self._materialized_dir, self._config.cache.materialized_ttl_seconds)
        self._last_cleanup = now

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        """
        Remove expired files and empty directories under a cache root.
        """
        if ttl_seconds <= 0:
            return
        now = time.time()
        skipped_files = 0
        for path in root.rglob("*"):
            try:
                if not path.is_file():
                    continue
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                path.unlink(missing_ok=True)
            except OSError as exc:
                skipped_files += 1
                self.logger.debug("Skipping cache file cleanup for %s: %s", path, exc)
        for path in sorted(root.rglob("*"), reverse=True):
            try:
                if not path.is_dir():
                    continue
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                path.rmdir()
            except OSError:
                continue
        if skipped_files:
            self.logger.warning(
                "Skipped cleanup of %d file(s) under %s due to permission/IO errors",
                skipped_files,
                root,
            )
