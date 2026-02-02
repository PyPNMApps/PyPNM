## Agent Review Bundle Summary
- Goal: Add retry support for transient TFTP upload failures and refine typing for upload checks.
- Changes: Added retry loop in _check_and_wait_for_tftp_upload with configurable attempts; typed filename as FileNameStr; added pytest for retry behavior.
- Files: src/pypnm/api/routes/common/extended/common_measure_service.py, src/pypnm/docsis/cm_snmp_operation.py, src/pypnm/pnm/lib/pnm_artifact_store.py, src/pypnm/snmp/snmp_v2c.py, src/pypnm/tools/tmp_cache_cleanup.py, tests/test_pnm_artifact_store.py, tests/test_snmp_v2c_set_with_retry.py, tests/test_tftp_upload_retry.py, tools/agent-review/2026-02-02-pnm-ingress-ttl-fix.part-1.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-1.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-2.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-3.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-4.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-5.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-6.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-7.review.md, tools/agent-review/2026-02-02-snmp-set-retry.part-8.review.md
- Tests: ruff check src; pytest -q
- Notes: Integration SNMP tests skipped (PNM_CM_IT=1 not set).
# FILE: src/pypnm/pnm/lib/pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
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
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        self._materialized_dir.mkdir(parents=True, exist_ok=True)

    def ingress_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return a writable ingress path for a capture file.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID to place the file in a scoped ingress folder.

        Returns
        -------
        Path
            Filesystem path where callers can write the ingress artifact.
        """
        if transaction_id:
            dest_dir = self._ingress_dir / str(transaction_id)
        else:
            dest_dir = self._ingress_dir / "untracked"
        dest_dir.mkdir(parents=True, exist_ok=True)
        return dest_dir / self._normalize_ingress_name(filename)

    def ingress_candidate_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return the expected ingress path without creating directories.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID to place the file in a scoped ingress folder.

        Returns
        -------
        Path
            Expected ingress location for the artifact.
        """
        if transaction_id:
            dest_dir = self._ingress_dir / str(transaction_id)
        else:
            dest_dir = self._ingress_dir / "untracked"
        return dest_dir / self._normalize_ingress_name(filename)

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
        matches = list(self._ingress_dir.rglob(target))
        if len(matches) == 1:
            return matches[0]
        return None

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
        digest = hashlib.sha256(str(source_path).encode()).hexdigest()[:12]
        name = source_path.name
        if name.endswith(".zst"):
            name = name[:-4]
        elif name.endswith(".gz"):
            name = name[:-3]
        return self._materialized_dir / str(transaction_id) / digest / name

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
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue
# FILE: src/pypnm/snmp/snmp_v2c.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025-2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterable
from datetime import datetime, timedelta, timezone
from typing import TypeVar

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    bulk_cmd,
    get_cmd,
    set_cmd,
    walk_cmd,
)
from pysnmp.proto.rfc1902 import (
    Counter32,
    Counter64,
    Gauge32,
    Integer,
    Integer32,
    IpAddress,
    OctetString,
)

from pypnm.config.pnm_config_manager import SystemConfigSettings
from pypnm.lib.constants import T
from pypnm.lib.inet import Inet
from pypnm.lib.inet_utils import InetGenerate
from pypnm.lib.types import (
    InetAddressStr,
    InterfaceIndex,
    OidStr,
    SnmpCommunity,
    SnmpIndex,
    SnmpReadCommunity,
    SnmpWriteCommunity,
)
from pypnm.snmp.compiled_oids import COMPILED_OIDS
from pypnm.snmp.modules import InetAddressType


class Snmp_v2c:
    """
    SNMPv2c Client for asynchronous GET, SET, and WALK operations.

    Attributes:
        host (str): Hostname or IP address of the SNMP agent.
        port (int): Port number used for SNMP (default is 161).
        read_community (str): Community string for SNMP GET/WALK (default from config).
        write_community (str): Community string for SNMP SET (default from config).
        _snmp_engine (SnmpEngine): Instance of pysnmp SnmpEngine.

    Class Attributes:
        COMPILE_MIBS (bool): Whether to compile MIBs for OID resolution.
        SNMP_PORT (int): Default SNMP port.

    Example:
        >>> snmp = Snmp_v2c(Inet('192.168.1.1'), community='public')
        >>> await snmp.get('1.3.6.1.2.1.1.1.0')
        >>> await snmp.walk('1.3.6.1.2.1.2')
        >>> await snmp.set('1.3.6.1.2.1.1.5.0', 'NewHostName')
        >>> snmp.close()
    """

    DISABLE = 1
    ENABLE = 2

    TRUE = 1
    FALSE = 2

    SNMP_PORT = 161

    SnmpValueType = (
        type[Integer32]
        | type[OctetString]
        | type[Integer]
        | type[Counter32]
        | type[Counter64]
        | type[Gauge32]
        | type[IpAddress]
    )

    def __init__(
        self,
        host: Inet,
        community: SnmpCommunity | None = None,
        read_community: SnmpReadCommunity | None = None,
        write_community: SnmpWriteCommunity | None = None,
        port: int = SNMP_PORT,
        timeout: int = SystemConfigSettings.snmp_timeout(),
        retries: int = SystemConfigSettings.snmp_retries(),
    ) -> None:
        """
        Initializes the SNMPv2c client.

        Args:
            host (Inet): Host address of the SNMP device.
            community (SnmpCommunity | None): Legacy community string for SNMP access.
            read_community (SnmpReadCommunity | None): Read community string override.
            write_community (SnmpWriteCommunity | None): Write community string override.
            port (int): SNMP port (default 161).
        """
        self.logger     = logging.getLogger(self.__class__.__name__)
        self._host      = host.inet
        self._port      = port
        if read_community is not None:
            self._read_community = str(read_community)
        elif community is not None:
            self._read_community = str(community)
        else:
            self._read_community = str(SystemConfigSettings.snmp_read_community())

        if write_community is not None:
            self._write_community = str(write_community)
        elif community is not None:
            self._write_community = str(community)
        else:
            self._write_community = str(SystemConfigSettings.snmp_write_community())

        if self._write_community == "":
            self._write_community = self._read_community
        self._timeout   = timeout
        self._retries   = retries
        self._snmp_engine = SnmpEngine()

    async def get(
        self,
        oid: str | tuple[str, str, int],
        timeout: float | None = None,
        retries: int | None = None,
    ) -> list[ObjectType] | None:
        """
        Perform an SNMP GET operation.

        Notes
        -----
        `timeout` for UdpTransportTarget.create(...) is in **seconds**, not milliseconds.

        Args:
            oid: OID to fetch, either as a numeric string, symbolic name, or tuple.
            timeout: Request timeout in **seconds**. If None, uses self._timeout.
            retries: Number of retries. If None, uses self._retries.

        Returns:
            Optional[List[ObjectType]]: List of SNMP variable bindings or None if no result.

        Raises:
            RuntimeError: On SNMP errors (transport/protocol).
        """
        self.logger.debug(f"Input OID: {oid}, timeout: {timeout}, retries: {retries}")

        resolved_oid = Snmp_v2c.resolve_oid(oid)
        obj = ObjectType(self._to_object_identity(resolved_oid))

        timeout_s = float(timeout if timeout is not None else self._timeout)
        retries_n = int(retries if retries is not None else self._retries)

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            self._snmp_engine,
            CommunityData(self._read_community, mpModel=1),
            await UdpTransportTarget.create((self._host, self._port),
                                            timeout=timeout_s,     # seconds
                                            retries=retries_n,     # count
                                            ),
            ContextData(),
            obj,
        )

        try:
            self._raise_on_snmp_error(errorIndication, errorStatus, errorIndex)
        except Exception as e:
            self.logger.error(f"Failed GET for OID {resolved_oid}: {e}")

        return varBinds

    async def walk(self, oid: str | tuple[str, str, int]) -> list[ObjectType] | None:
        """
        Perform an SNMP WALK operation.

        Args:
            oid (str | Tuple[str, str, int]): The starting OID for the walk.

        Returns:
            Optional[List[ObjectType]]: List of walked SNMP ObjectTypes, or None if no results.
        """
        self.logger.debug(f"Starting SNMP WALK with OID: {oid}")
        oid = Snmp_v2c.resolve_oid(oid)
        self.logger.debug(f"Converted: {oid}")

        identity = self._to_object_identity(oid)
        obj = ObjectType(identity)
        results: list[ObjectType] = []

        transport = await UdpTransportTarget.create((self._host, self._port),
                                                    timeout=self._timeout,
                                                    retries=self._retries)

        objects = walk_cmd(
            self._snmp_engine,
            CommunityData(self._read_community, mpModel=1),
            transport,
            ContextData(),
            obj
        )

        async for item in objects:

            errorIndication, errorStatus, errorIndex, varBinds = item

            try:
                self._raise_on_snmp_error(errorIndication, errorStatus, errorIndex)

            except Exception as e:
                self.logger.error(f"Failed walk : {e}")
                continue

            if not varBinds:
                continue

            for varBind in varBinds:
                oid_str = str(varBind[0])

                if not self._is_oid_in_subtree(oid_str, str(identity)):
                    self.logger.debug(f"End of OID subtree reached at {oid_str} -> {varBind} - List size {len(results)}")
                    return results if results else None

                results.append(varBind)

        self.logger.debug(f'List size {len(results)}')

        return results if results else None

    async def bulk_walk(
        self,
        oid: str | tuple[str, str, int],
        non_repeaters: int = 0,
        max_repetitions: int = 25,
        suppress_no_such_name: bool = True,
    ) -> list[ObjectType] | None:
        """
        Perform an SNMP GETBULK operation (faster alternative to WALK).

        GETBULK is an SNMPv2c/v3 operation that retrieves multiple variables
        in a single request, making it significantly faster than traditional
        WALK operations for large tables.

        Args:
            oid (str | Tuple[str, str, int]): The starting OID for the bulk walk.
            non_repeaters (int): Number of OIDs from the start that should not be repeated.
                                 Default is 0 (repeat all).
            max_repetitions (int): Maximum number of repetitions for repeating variables.
                                   Default is 25. Higher values = fewer requests but
                                   larger packets. Typical range: 10-50.

        Returns:
            Optional[List[ObjectType]]: List of SNMP ObjectTypes retrieved, or None if no results.

        Notes:
            - GETBULK is more efficient than WALK for large MIB tables
            - Not supported by SNMPv1 agents (will fall back to WALK)
            - max_repetitions should be tuned based on network conditions:
              * Small networks: 25-50
              * Large/slow networks: 10-25
              * Very fast networks: 50-100
        """
        oid = Snmp_v2c.resolve_oid(oid)

        identity = self._to_object_identity(oid)
        attempt_values: list[int] = []
        for value in [max_repetitions, 10, 5, 1]:
            if value > 0 and value not in attempt_values:
                attempt_values.append(value)

        last_error: str | None = None

        for attempt in attempt_values:
            self.logger.debug(
                f"Starting SNMP BULK WALK with OID: {oid}, non_repeaters={non_repeaters}, max_repetitions={attempt}"
            )
            obj = ObjectType(identity)
            results: list[ObjectType] = []
            retry = False
            hard_error = False

            transport = await UdpTransportTarget.create(
                (self._host, self._port),
                timeout=self._timeout,
                retries=self._retries
            )

            objects = await bulk_cmd(
                self._snmp_engine,
                CommunityData(self._read_community, mpModel=1),
                transport,
                ContextData(),
                non_repeaters,
                attempt,
                obj
            )

            def _process_item(
                item: tuple[object, object, object, list[ObjectType]],
                attempt_value: int,
                identity_value: object,
                results_list: list[ObjectType],
            ) -> tuple[bool, bool, bool, str | None]:
                errorIndication, errorStatus, errorIndex, varBinds = item

                if errorIndication or errorStatus:
                    status_text = ""
                    if errorStatus:
                        pretty = getattr(errorStatus, "prettyPrint", None)
                        status_text = pretty() if callable(pretty) else str(errorStatus)
                    error_message = status_text or str(errorIndication)

                    if status_text == "tooBig":
                        self.logger.warning(
                            f"Bulk walk tooBig with max_repetitions={attempt_value}; retrying with smaller value."
                        )
                        return True, True, False, error_message

                    if status_text == "noSuchName" and suppress_no_such_name:
                        self.logger.debug(f"Failed bulk walk: {error_message}")
                    else:
                        self.logger.error(f"Failed bulk walk: {error_message}")
                    return True, False, True, error_message

                if not varBinds:
                    return False, False, False, None

                for varBind in varBinds:
                    oid_str = str(varBind[0])

                    if not self._is_oid_in_subtree(oid_str, str(identity_value)):
                        self.logger.debug   (
                            f"End of OID subtree reached at {oid_str} -> {varBind} - List size {len(results_list)}"
                        )
                        return True, False, False, None

                    results_list.append(varBind)

                return False, False, False, None

            if isinstance(objects, tuple) and len(objects) == 4:
                done, retry, hard_error, error_message = _process_item(
                    objects,
                    attempt,
                    identity,
                    results,
                )
                if error_message:
                    last_error = error_message
                if done and results:
                    return results
            elif isinstance(objects, AsyncIterable):
                async for item in objects:
                    done, retry, hard_error, error_message = _process_item(
                        item,
                        attempt,
                        identity,
                        results,
                    )
                    if error_message:
                        last_error = error_message
                    if done:
                        if results:
                            return results
                        break
            else:
                last_error = f"unexpected bulk_cmd result type: {type(objects).__name__}"
                self.logger.error(f"Failed bulk walk: {last_error}")
                hard_error = True

            if hard_error:
                break
            if results:
                self.logger.debug(f'Bulk walk completed - List size {len(results)}')
                return results
            if retry:
                continue

            self.logger.debug(f"Bulk walk returned no data with max_repetitions={attempt}.")

        if last_error:
            if last_error == "noSuchName" and suppress_no_such_name:
                self.logger.debug(f"Bulk walk failed or empty ({last_error}); falling back to walk.")
            else:
                self.logger.warning(f"Bulk walk failed or empty ({last_error}); falling back to walk.")
        else:
            self.logger.warning("Bulk walk returned no data; falling back to walk.")

        return await self.walk(oid)

    async def set(
        self,
        oid: OidStr,
        value: str | int,
        value_type: SnmpValueType,
    ) -> list[ObjectType] | None:
        """
        Perform an SNMP SET operation with explicit value type.

        Args:
            oid (str): The OID to set.
            value (Union[str, int]): The value to set.
            value_type (Type): pysnmp value type class (no default).

                Examples:
                    OctetString, Integer, Integer32, Counter32, Counter64, Gauge32, IpAddress.

        Returns:
            Dict[str, str]: Mapping of OID to the set value.

        Raises:
            ValueError: If value type instantiation fails.
            RuntimeError: On SNMP errors.
        """
        var_binds, _ = await self._set_once(oid=oid, value=value, value_type=value_type)
        return var_binds

    async def set_with_retry(
        self,
        oid: OidStr,
        value: str | int,
        value_type: SnmpValueType,
        retries: int = 3,
        base_delay_seconds: float = 0.2,
        backoff: float = 2.0,
    ) -> list[ObjectType] | None:
        """
        Perform an SNMP SET with retry behavior for resourceUnavailable errors.

        Args:
            oid (str): The OID to set.
            value (str | int): The value to set.
            value_type (type): pysnmp value type class.
            retries (int): Total attempts (including the first).
            base_delay_seconds (float): Initial delay before retrying.
            backoff (float): Multiplicative backoff for each retry.

        Returns:
            list[ObjectType] | None: SNMP varBinds when successful, otherwise None.
        """
        attempts = retries if retries > 0 else 1
        delay = base_delay_seconds
        last_error: str | None = None

        for attempt in range(1, attempts + 1):
            var_binds, error_text = await self._set_once(oid=oid, value=value, value_type=value_type)
            if var_binds is not None:
                return var_binds

            last_error = error_text

            if error_text is None:
                break

            if not self._is_resource_unavailable_error(error_text):
                break

            if attempt < attempts:
                self.logger.warning(
                    "SNMP SET resourceUnavailable; retrying (%d/%d) after %.2fs. OID=%s",
                    attempt,
                    attempts,
                    delay,
                    oid,
                )
                await asyncio.sleep(delay)
                delay *= backoff

        if last_error:
            self.logger.error("SNMP SET failed after retries: %s", last_error)

        return None

    async def _set_once(
        self,
        oid: OidStr,
        value: str | int,
        value_type: SnmpValueType,
    ) -> tuple[list[ObjectType] | None, str | None]:
        """
        Perform a single SNMP SET and return varBinds and error text.
        """
        if value_type is None:
            raise ValueError("value_type must be explicitly specified")

        self.logger.debug(f'SNMP-SET-OID: {oid} -> {value_type} -> {value}')

        oid = Snmp_v2c.resolve_oid(oid)

        transport = await UdpTransportTarget.create((self._host, self._port),
                                                    timeout=self._timeout, retries=self._retries)

        try:
            snmp_value = value_type(value)
        except Exception as e:
            raise ValueError(f"Failed to create SNMP value of type {value_type}: {e}") from e

        errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
            self._snmp_engine,
            CommunityData(self._write_community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid), snmp_value),
        )

        error_text = self._format_snmp_error(errorIndication, errorStatus, errorIndex)
        if error_text:
            self.logger.error("Error extracting SNMP value: %s", error_text)
            return None, error_text

        return varBinds, None # type: ignore

    @staticmethod
    def _format_snmp_error(
        errorIndication: Exception | str | None,
        errorStatus: object | None,
        errorIndex: Integer32 | int | None,
    ) -> str | None:
        """
        Build a consistent error string from SNMP errors, if any.
        """
        if errorIndication:
            return f"SNMP operation failed: {errorIndication}"

        if errorStatus:
            pretty = getattr(errorStatus, "prettyPrint", None)
            status_text = pretty() if callable(pretty) else str(errorStatus)
            return f"SNMP error {status_text} at index {errorIndex}"

        return None

    @staticmethod
    def _is_resource_unavailable_error(error_text: str) -> bool:
        """
        Check whether the SNMP error indicates a resourceUnavailable response.
        """
        return "resourceUnavailable" in error_text

    def close(self) -> None:
        """
        Close the SNMP engine dispatcher and release resources.
        """
        self._snmp_engine.close_dispatcher()

    @staticmethod
    def resolve_oid(oid: str | tuple[str, str, int]) -> str:
        """
        Resolves symbolic OIDs with optional numeric suffixes.

        Examples:
            'ifDescr'             → '1.3.6.1.2.1.2.2.1.2'
            'ifDescr.2'           → '1.3.6.1.2.1.2.2.1.2.2'
            '1.3.6.1.2.1.2.2.1.2' → '1.3.6.1.2.1.2.2.1.2' (unchanged)

        Returns:
            str: Fully resolved numeric OID string.
        """
        if isinstance(oid, tuple):
            # Optional support for Tuple format: (base, suffix1, suffix2)
            oid = '.'.join(map(str, oid))

        if Snmp_v2c.is_numeric_oid(oid):
            return oid

        # Split symbolic base from numeric suffix
        match = re.match(r"^([a-zA-Z0-9_:]+)(\..+)?$", oid)
        if not match:
            return oid  # fallback: invalid pattern

        base_sym, suffix = match.groups()
        base_num = COMPILED_OIDS.get(base_sym, base_sym)
        return f"{base_num}{suffix or ''}"

    @staticmethod
    def is_numeric_oid(oid: str) -> bool:
        """
        Returns True if the OID string is numeric.

        Accepted formats:
            - '1.3.6.1.2.1.2.2.1.2'
            - '.1.3.6.1.2.1.2.2.1.2'  (leading dot is allowed)

        Returns:
            bool: True if the OID is numeric, False otherwise.
        """
        return bool(re.fullmatch(r"\.?(\d+\.)+\d+", oid))

    @staticmethod
    def get_result_value(pysnmp_get_result: ObjectType | tuple[ObjectType, ...] | None) -> str | None:
        """
        Extract the value from a pysnmp GET result.

        Args:
            pysnmp_get_result: SNMP response from get().

        Returns:
            Optional[str]: The extracted value as string, or None if not found.
        """
        try:
            if isinstance(pysnmp_get_result, tuple):
                pysnmp_get_result = pysnmp_get_result[0]

            if isinstance(pysnmp_get_result, ObjectType):
                value = pysnmp_get_result[1]
                if isinstance(value, OctetString):
                    return value.prettyPrint()
                return str(value)

            return None

        except Exception as e:
            logging.debug(f"Error extracting SNMP value: {e}")
            return None

    @staticmethod
    def extract_last_oid_index(snmp_responses: list[ObjectType]) -> list[int]:
        """
        Extract the last index from a list of SNMP responses.

        Parameters:
        - snmp_responses: List of SNMP responses.

        Returns:
        - List of extracted indices.
        """
        last_oid_indexes = []
        for response in snmp_responses:
            oid = response[0]
            index = Snmp_v2c.get_oid_index(oid)
            logging.debug(f'extract_last_oid_index-IN-LOOP -> {response} -> {oid} -> {index}')
            last_oid_indexes.append(index)
        return last_oid_indexes

    @staticmethod
    def extract_oid_indices(snmp_responses: list[ObjectType],num_indices: int = 1) -> list[list[SnmpIndex]]:
        """
        Extract the last `num_indices` components from the OID index of each SNMP response.

        Parameters:
        - snmp_responses: List of SNMP responses.
        - num_indices: Number of trailing OID index components to extract.

        Returns:
        - List of lists, each containing the extracted index components.
        """
        extracted_indices:list[list[SnmpIndex]] = []

        for response in snmp_responses:
            oid = response[0]
            full_index = Snmp_v2c.get_oid_index(oid)

            if isinstance(full_index, int):
                indices = [full_index]
            elif isinstance(full_index, (list, tuple)):
                indices = list(full_index)
            else:
                logging.warning(f"Unexpected OID index format: {full_index}")
                continue

            selected = indices[-num_indices:] if len(indices) >= num_indices else indices
            logging.debug(f"extract_oid_indices -> {response} -> {oid} -> {selected}")
            extracted_indices.append(selected)

        return extracted_indices

    @staticmethod
    def snmp_get_result_value(snmp_responses: list[ObjectType]) -> list[str]:
        """
        Extract the result value from a list of SNMP responses.

        Args:
            snmp_responses (List[ObjectType]): List of SNMP ObjectType responses.

        Returns:
            List[str]: List of extracted result values as strings.
        """
        return [str(value[1]) for value in snmp_responses]

    @staticmethod
    def snmp_get_result_bytes(snmp_responses: list[ObjectType]) -> list[bytes]:
        """
        Extract raw byte values from a list of SNMP ObjectType responses.

        Args:
            snmp_responses (List[ObjectType]): List of SNMP ObjectType responses.

        Returns:
            List[bytes]: List of extracted result values as bytes.
        """
        result = []
        for varbind in snmp_responses:
            value = varbind[1]
            result.append(Snmp_v2c.snmp_octets_to_bytes(value))
        return result

    @staticmethod
    def snmp_octets_to_bytes(value: object) -> bytes:
        """
        Normalize SNMP OctetString-like values into raw bytes.

        Supports bytes/bytearray/memoryview, pysnmp objects exposing asOctets(),
        or objects that can be converted via bytes(). Returns b"" on failure.
        """
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)

        as_octets = getattr(value, "asOctets", None)
        if callable(as_octets):
            try:
                return bytes(as_octets())
            except Exception:
                return b""

        try:
            return bytes(value)
        except Exception:
            return b""

    @staticmethod
    def snmp_get_result_last_idx_value(snmp_responses: list[ObjectType]) -> list[tuple[InterfaceIndex, str]]:
        """
        Extract the last index and value from each SNMP response.

        Args:
            snmp_responses (List[ObjectType]): List of SNMP ObjectType responses.

        Returns:
            List[Tuple[InterfaceIndex, str]]: List of (last InterfaceIndex, value) pairs.
        """
        result = []
        for obj in snmp_responses:
            oid = obj[0]
            last_idx = InterfaceIndex(int(str(oid).split('.')[-1]))
            value = str(obj[1])
            result.append((last_idx, value))
        return result

    T = TypeVar("T", int, str)
    @staticmethod
    def snmp_get_result_last_idx_force_value_type(snmp_responses: list[ObjectType],
                                                  value_type: type[T] = str) -> list[tuple[int, T]]:
        """
        Extract the last index and value from each SNMP response,
        casting the value to the requested type (int or str).

        Args:
            snmp_responses: List of SNMP ObjectType responses.
            value_type: Type to cast the SNMP value to (int or str). Defaults to str.

        Returns:
            List of (last index, value) pairs, where `value` is of type `value_type`.
        """
        logger = logging.getLogger(__name__)
        result: list[tuple[int, T]] = []

        for obj in snmp_responses:
            # 1) extract index
            try:
                oid_str = str(obj[0])
                last_idx = int(oid_str.rsplit(".", 1)[-1])
            except Exception as e:
                logger.warning(f"Could not parse index from OID {obj[0]!r}: {e}")
                continue

            # 2) cast value
            raw_val = obj[1]
            try:
                if value_type is int:
                    cast_val: int | str = int(raw_val)
                else:
                    cast_val = str(raw_val)
            except Exception as e:
                logger.warning(f"Failed to cast SNMP value {raw_val!r} to {value_type}: {e}")
                # fallback: leave it in its raw form
                cast_val = raw_val  # type: ignore

            result.append((last_idx, cast_val))  # type: ignore

        return result

    @staticmethod
    def snmp_set_result_value(snmp_set_response: str) -> list[str]:
        """
        Extracts value(s) from an SNMP SET response string.

        This method parses the raw SNMP SET response string and extracts the
        returned value(s), if any, from the output. Useful for validating
        SNMP set operations.

        Parameters:
        - snmp_set_response (str): The raw SNMP SET response string, typically
        returned by an SNMP set operation.

        Returns:
        - List[str]: A list containing the parsed value(s) from the response.
                    If no value is found, returns an empty list.
        """
        if not snmp_set_response:
            return []

        logging.debug(f'snmp_set_result_value -> {snmp_set_response}')

        return  [str(value[1]) for value in snmp_set_response]

    @staticmethod
    def get_oid_index(oid: str) -> SnmpIndex | None:
        """
        Extract the index (last sub-identifier) from an OID string.

        Args:
            oid (str): The OID in dot-separated format (e.g., '1.3.6.1.2.1.2.2.1.3.2').

        Returns:
            Optional[int]: The last part of the OID interpreted as an integer, or None if extraction fails.
        """
        if not isinstance(oid, str):
            oid = str(oid)

        try:
            parts = oid.strip().split('.')
            index = SnmpIndex(int(parts[-1]))
            logging.debug(f"Extracted OID index: OID='{oid}', Parts={parts}, Index={index}")
            return index
        except (ValueError, IndexError) as e:
            logging.error(f"Failed to extract index from OID '{oid}': {e}")
            return None

    @staticmethod
    def get_inet_address_type(inet_address: InetAddressStr) -> InetAddressType:
        """
        Determine the InetAddressType of an IP address (IPv4 or IPv6).

        Args:
            inet_address (str): The IP address to check.

        Returns:
            InetAddressType: IPV4 (1) for IPv4 addresses, or IPV6 (2) for IPv6 addresses.

        Raises:
            ValueError: If the IP address is invalid.
        """
        binary = InetGenerate.inet_to_binary(inet_address)

        if not binary:
            raise ValueError(f"Invalid IP address: {inet_address}")

        return InetAddressType.IPV6 if len(binary) > 4 else InetAddressType.IPV4

    @staticmethod
    def parse_snmp_datetime(data: bytes) -> str:
        """
        Parses SNMP DateAndTime byte array and returns an ISO 8601 datetime string.

        Args:
            data (bytes): SNMP DateAndTime value as a byte array.

        Returns:
            str: ISO 8601 formatted datetime string (e.g., "2025-05-02T13:15:00").
        """
        if len(data) < 8:
            raise ValueError("Invalid SNMP DateAndTime data (too short)")

        # Convert the raw bytes into integer values
        year = data[0] << 8 | data[1]
        month = data[2]
        day = data[3]
        hour = data[4]
        minute = data[5]
        second = data[6]

        # Default: naive datetime (no timezone info)
        dt = datetime(year, month, day, hour, minute, second)

        if len(data) >= 11:
            # Timezone info exists
            direction = chr(data[8])
            tz_hours = data[9]
            tz_minutes = data[10]
            offset_minutes = tz_hours * 60 + tz_minutes
            if direction == '-':
                offset_minutes = -offset_minutes
            tz = timezone(timedelta(minutes=offset_minutes))
            dt = dt.replace(tzinfo=tz)

        return dt.isoformat()

    @staticmethod
    def truth_value(snmp_value: int | str) -> bool:
        """
        Converts SNMP TruthValue integer to a boolean.

        TruthValue ::= INTEGER { true(1), false(2) }

        Args:
            snmp_value (int or str): The raw SNMP integer value or string representation.

        Returns:
            bool: True if value is 1 (true), False if 2 (false).

        Raises:
            ValueError: If the value is not 1 or 2.
        """
        # Attempt to convert the snmp_value to an integer
        try:
            snmp_value = int(snmp_value)
        except ValueError:
            raise ValueError(f"Invalid input for TruthValue: {snmp_value}") from None

        if snmp_value == 1:
            return True
        elif snmp_value == 2:
            return False
        else:
            raise ValueError(f"Invalid TruthValue: {snmp_value}")

    @staticmethod
    def ticks_to_duration(ticks: int) -> str:
        """
        Converts SNMP sysUpTime ticks to a human-readable duration string.

        SNMP uptime ticks are measured in hundredths of a second.

        Args:
            ticks (int): The sysUpTime value in hundredths of a second.

        Returns:
            str: A formatted duration string like '3 days, 4:05:06.78'
        """
        if ticks < 0:
            raise ValueError("Ticks must be a non-negative integer")

        # Convert hundredths of a second to total seconds and microseconds
        total_seconds = ticks // 100
        remainder_hundredths = ticks % 100
        duration = timedelta(seconds=total_seconds, milliseconds=remainder_hundredths * 10)

        return str(duration)


    ###################
    # Private Methods #
    ###################

    def _to_object_identity(self, oid: str | tuple[str, str, int]) -> ObjectIdentity:
        """
        Internal helper to resolve an OID.

        Args:
            oid (Union[str, Tuple[str, str, int]]): OID to resolve.

        Returns:
            ObjectIdentity: pysnmp ObjectIdentity.
        """
        if isinstance(oid, tuple):
            self.logger.debug(f"Resolving OID tuple: {oid}")
            return ObjectIdentity(*oid)
        else:
            self.logger.debug(f"Resolving OID string: {oid}")
            return ObjectIdentity(oid)

    def _raise_on_snmp_error(self, errorIndication: Exception | str | None, errorStatus: object | None, errorIndex: Integer32 | int | None) -> None:
        """
        Raises RuntimeError if any SNMP error is detected.

        Args:
            errorIndication: General SNMP engine-level error (e.g., timeout, transport failure).
                            Typically an Exception instance or an error string, or None.
            errorStatus: SNMP protocol-level error (e.g., noSuchName, tooBig) or None.
            errorIndex: Index of the variable that caused the error (if applicable).

        Raises:
            RuntimeError: If an SNMP error or indication is present.
        """
        if errorIndication:
            raise RuntimeError(f"SNMP operation failed: {errorIndication}")
        if errorStatus:
            # errorStatus objects from pysnmp typically expose prettyPrint()
            pretty = getattr(errorStatus, "prettyPrint", None)
            status_text = pretty() if callable(pretty) else str(errorStatus)
            raise RuntimeError(
                f"SNMP error {status_text} at index {errorIndex}"
            )

    def _is_oid_in_subtree(self, oid_str: str, obj_str: str) -> bool:
        """
        Check if an OID is part of the requested subtree.

        Args:
            oid_str (str): The current OID string (e.g., '1.3.6.1.2.1.2.2.1.2.5').
            obj_str (str): The requested root OID string (e.g., '1.3.6.1.2.1.2.2.1.2').

        Returns:
            bool: True if oid_str is within the subtree of obj_str.
        """
        oid_parts = oid_str.strip('.').split('.')
        obj_parts = obj_str.strip('.').split('.')
        return oid_parts[:len(obj_parts)] == obj_parts
# FILE: src/pypnm/tools/tmp_cache_cleanup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import time
from pathlib import Path

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class TmpCacheCleaner:
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._tmp_root = Path(self._config.cache.tmp_root)

    def run(self) -> int:
        """
        Clean expired ingress and materialized cache entries.

        Returns:
            int: Process exit code (0 for success).
        """
        ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        materialized_dir = self._tmp_root / self._config.cache.materialized_dir

        self._cleanup_dir(ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(materialized_dir, self._config.cache.materialized_ttl_seconds)
        return 0

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if not root.exists():
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
# FILE: tests/test_pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import time
from pathlib import Path

from pypnm.config.pnm_artifact_storage import (
    ArtifactCacheConfig,
    ArtifactCompressionPolicyConfig,
    PnmArtifactStorageConfig,
)
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


def _build_config(tmp_root: Path, min_bytes: int) -> PnmArtifactStorageConfig:
    return PnmArtifactStorageConfig(
        compression=ArtifactCompressionPolicyConfig(
            enabled=True,
            min_bytes=min_bytes,
            conditional_max_ratio=0.92,
            conditional_min_savings_bytes=8192,
            deny=[],
            always=["test_type"],
            conditional=[],
            primary_codec="gzip",
            gzip_fallback=False,
            zstd_level=3,
            gzip_level=6,
        ),
        cache=ArtifactCacheConfig(
            tmp_root=str(tmp_root),
            ingress_dir="ingress",
            materialized_dir="materialized",
            ingress_ttl_seconds=900,
            materialized_ttl_seconds=86400,
            cleanup_interval_seconds=0,
        ),
    )


def test_commit_ingress_file_gzip_compresses(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx1")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    ingress.write_bytes(b"0" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith(".gz")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is True
    assert result.size_after < result.size_before


def test_commit_ingress_file_min_bytes_skips_compression(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=20000)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    ingress = store.ingress_path(FileNameStr("test.bin"), TransactionId("tx2"))
    ingress.write_bytes(b"1" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith("test.bin")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is False


def test_materialize_decompresses_gzip(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx3")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    payload = b"abc" * 5000
    ingress.write_bytes(payload)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    materialized = store.materialize(txn_id, result.stored_filename, result.compression)

    assert materialized.read_bytes() == payload


def test_resolve_physical_path_prefers_raw_when_missing_compressed(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    raw_path = pnm_dir / "raw.bin"
    raw_path.write_bytes(b"raw")

    compression = {
        "is_compressed": True,
        "codec": "zstd",
        "level": 3,
        "size_before": 3,
        "size_after": 2,
    }
    resolved = store.resolve_physical_path(FileNameStr("raw.bin"), compression)
    assert resolved == raw_path


def test_cleanup_dir_keeps_recent_empty_dirs(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    recent = store.ingress_path(FileNameStr("recent.bin"), TransactionId("recent"))
    recent_dir = recent.parent

    old_dir = store.ingress_path(FileNameStr("old.bin"), TransactionId("old")).parent
    old_time = time.time() - 1000
    os.utime(old_dir, (old_time, old_time))

    store._cleanup_dir(store._ingress_dir, ttl_seconds=900)

    assert recent_dir.exists()
    assert not old_dir.exists()
# FILE: tests/test_snmp_v2c_set_with_retry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

from types import MethodType

import pytest
from pysnmp.hlapi.v3arch.asyncio import ObjectType

from pypnm.lib.inet import Inet
from pypnm.snmp.snmp_v2c import Snmp_v2c


@pytest.mark.asyncio
async def test_set_with_retry_retries_on_resource_unavailable() -> None:
    snmp = Snmp_v2c(host=Inet("127.0.0.1"))
    calls: list[int] = []

    async def fake_set_once(
        self: Snmp_v2c,
        oid: str,
        value: str | int,
        value_type: Snmp_v2c.SnmpValueType,
    ) -> tuple[list[ObjectType] | None, str | None]:
        calls.append(1)
        if len(calls) < 3:
            return None, "SNMP error resourceUnavailable at index 1"
        return [], None

    snmp._set_once = MethodType(fake_set_once, snmp)

    response = await snmp.set_with_retry(
        oid="1.2.3.4.5",
        value=1,
        value_type=int,
        retries=3,
        base_delay_seconds=0.0,
        backoff=1.0,
    )

    assert response == []
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_set_with_retry_does_not_retry_on_other_errors() -> None:
    snmp = Snmp_v2c(host=Inet("127.0.0.1"))
    calls: list[int] = []

    async def fake_set_once(
        self: Snmp_v2c,
        oid: str,
        value: str | int,
        value_type: Snmp_v2c.SnmpValueType,
    ) -> tuple[list[ObjectType] | None, str | None]:
        calls.append(1)
        return None, "SNMP error undoFailed at index 1"

    snmp._set_once = MethodType(fake_set_once, snmp)

    response = await snmp.set_with_retry(
        oid="1.2.3.4.5",
        value=1,
        value_type=int,
        retries=3,
        base_delay_seconds=0.0,
        backoff=1.0,
    )

    assert response is None
    assert len(calls) == 1
# FILE: tests/test_tftp_upload_retry.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace

import pytest

from pypnm.api.routes.common.extended.common_measure_service import CommonMeasureService
from pypnm.docsis.cm_snmp_operation import DocsPnmBulkFileUploadStatus
from pypnm.lib.utils import Generate
from pypnm.pnm.data_type.pnm_test_types import DocsPnmCmCtlTest


@pytest.mark.asyncio
async def test_tftp_upload_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    service = CommonMeasureService.__new__(CommonMeasureService)
    service.logger = logging.getLogger("CommonMeasureService")
    service.log_prefix = "CommonMeasureService"
    service.pnm_test_type = DocsPnmCmCtlTest.DS_OFDM_RXMER_PER_SUBCAR
    service.pnm_dir = ".data/pnm"
    service.cm = SimpleNamespace()

    statuses = [
        DocsPnmBulkFileUploadStatus.ERROR,
        DocsPnmBulkFileUploadStatus.UPLOAD_COMPLETED,
    ]

    async def fake_status(filename: str) -> DocsPnmBulkFileUploadStatus:
        return statuses.pop(0)

    async def fake_sleep(_: float) -> None:
        return None

    service.cm.getBulkFileUploadStatus = fake_status
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    filename = f"unit-test-{Generate.time_stamp()}.bin"
    result = await service._check_and_wait_for_tftp_upload(filename, max_wait_count=1, retries=5)

    assert result.name == "SUCCESS"
# FILE: tools/agent-review/2026-02-02-pnm-ingress-ttl-fix.part-1.review.md
## Agent Review Bundle Summary
- Goal: Fix ingress cache cleanup removing recent empty dirs and update tmp cache cleanup tool accordingly.
- Changes: Keep recent empty ingress/materialized dirs until TTL expires; align tmp cleanup paths with config; add cleanup tests for recent vs old empty dirs.
- Files: src/pypnm/pnm/lib/pnm_artifact_store.py, src/pypnm/tools/tmp_cache_cleanup.py, tests/test_pnm_artifact_store.py
- Tests: pytest -q
- Notes: Integration SNMP tests skipped (PNM_CM_IT=1 not set).
# FILE: src/pypnm/pnm/lib/pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import hashlib
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
        self._ingress_dir.mkdir(parents=True, exist_ok=True)
        self._materialized_dir.mkdir(parents=True, exist_ok=True)

    def ingress_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return a writable ingress path for a capture file.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID to place the file in a scoped ingress folder.

        Returns
        -------
        Path
            Filesystem path where callers can write the ingress artifact.
        """
        if transaction_id:
            dest_dir = self._ingress_dir / str(transaction_id)
        else:
            dest_dir = self._ingress_dir / "untracked"
        dest_dir.mkdir(parents=True, exist_ok=True)
        return dest_dir / self._normalize_ingress_name(filename)

    def ingress_candidate_path(self, filename: FileNameStr, transaction_id: TransactionId | None = None) -> Path:
        """
        Return the expected ingress path without creating directories.

        Parameters
        ----------
        filename:
            Target filename for the ingress copy (normalized to raw filename).
        transaction_id:
            Optional transaction ID to place the file in a scoped ingress folder.

        Returns
        -------
        Path
            Expected ingress location for the artifact.
        """
        if transaction_id:
            dest_dir = self._ingress_dir / str(transaction_id)
        else:
            dest_dir = self._ingress_dir / "untracked"
        return dest_dir / self._normalize_ingress_name(filename)

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
        matches = list(self._ingress_dir.rglob(target))
        if len(matches) == 1:
            return matches[0]
        return None

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
        digest = hashlib.sha256(str(source_path).encode()).hexdigest()[:12]
        name = source_path.name
        if name.endswith(".zst"):
            name = name[:-4]
        elif name.endswith(".gz"):
            name = name[:-3]
        return self._materialized_dir / str(transaction_id) / digest / name

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
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue
# FILE: src/pypnm/tools/tmp_cache_cleanup.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import logging
import time
from pathlib import Path

from pypnm.config.config_manager import ConfigManager
from pypnm.config.pnm_artifact_storage import PnmArtifactStorageConfig


class TmpCacheCleaner:
    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        config = ConfigManager().get("PnmArtifactStorage")
        self._config = PnmArtifactStorageConfig.from_config(config if isinstance(config, dict) else None)
        self._tmp_root = Path(self._config.cache.tmp_root)

    def run(self) -> int:
        ingress_dir = self._tmp_root / self._config.cache.ingress_dir
        materialized_dir = self._tmp_root / self._config.cache.materialized_dir

        self._cleanup_dir(ingress_dir, self._config.cache.ingress_ttl_seconds)
        self._cleanup_dir(materialized_dir, self._config.cache.materialized_ttl_seconds)
        return 0

    def _cleanup_dir(self, root: Path, ttl_seconds: int) -> None:
        if ttl_seconds <= 0:
            return
        if not root.exists():
            return
        now = time.time()
        for path in root.rglob("*"):
            if path.is_file():
                age = now - path.stat().st_mtime
                if age >= ttl_seconds:
                    path.unlink(missing_ok=True)
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_dir():
                age = now - path.stat().st_mtime
                if age < ttl_seconds:
                    continue
                try:
                    path.rmdir()
                except OSError:
                    continue


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return TmpCacheCleaner().run()


if __name__ == "__main__":
    raise SystemExit(main())
# FILE: tests/test_pnm_artifact_store.py
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Maurice Garcia

from __future__ import annotations

import os
import time
from pathlib import Path

from pypnm.config.pnm_artifact_storage import (
    ArtifactCacheConfig,
    ArtifactCompressionPolicyConfig,
    PnmArtifactStorageConfig,
)
from pypnm.lib.types import FileNameStr, TransactionId
from pypnm.pnm.lib.pnm_artifact_store import PnmArtifactStore


def _build_config(tmp_root: Path, min_bytes: int) -> PnmArtifactStorageConfig:
    return PnmArtifactStorageConfig(
        compression=ArtifactCompressionPolicyConfig(
            enabled=True,
            min_bytes=min_bytes,
            conditional_max_ratio=0.92,
            conditional_min_savings_bytes=8192,
            deny=[],
            always=["test_type"],
            conditional=[],
            primary_codec="gzip",
            gzip_fallback=False,
            zstd_level=3,
            gzip_level=6,
        ),
        cache=ArtifactCacheConfig(
            tmp_root=str(tmp_root),
            ingress_dir="ingress",
            materialized_dir="materialized",
            ingress_ttl_seconds=900,
            materialized_ttl_seconds=86400,
            cleanup_interval_seconds=0,
        ),
    )


def test_commit_ingress_file_gzip_compresses(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx1")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    ingress.write_bytes(b"0" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith(".gz")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is True
    assert result.size_after < result.size_before


def test_commit_ingress_file_min_bytes_skips_compression(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=20000)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    ingress = store.ingress_path(FileNameStr("test.bin"), TransactionId("tx2"))
    ingress.write_bytes(b"1" * 10000)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    assert str(result.stored_filename).endswith("test.bin")
    assert result.compression is not None
    assert result.compression.get("is_compressed") is False


def test_materialize_decompresses_gzip(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    txn_id = TransactionId("tx3")
    ingress = store.ingress_path(FileNameStr("test.bin"), txn_id)
    payload = b"abc" * 5000
    ingress.write_bytes(payload)

    result = store.commit_ingress_file("test_type", ingress, FileNameStr("test.bin"))
    materialized = store.materialize(txn_id, result.stored_filename, result.compression)

    assert materialized.read_bytes() == payload


def test_resolve_physical_path_prefers_raw_when_missing_compressed(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    raw_path = pnm_dir / "raw.bin"
    raw_path.write_bytes(b"raw")

    compression = {
        "is_compressed": True,
        "codec": "zstd",
        "level": 3,
        "size_before": 3,
        "size_after": 2,
    }
    resolved = store.resolve_physical_path(FileNameStr("raw.bin"), compression)
    assert resolved == raw_path


def test_cleanup_dir_keeps_recent_empty_dirs(tmp_path: Path) -> None:
    cfg = _build_config(tmp_path / "tmp", min_bytes=0)
    pnm_dir = tmp_path / "pnm"
    store = PnmArtifactStore(config=cfg, pnm_dir=pnm_dir)

    recent = store.ingress_path(FileNameStr("recent.bin"), TransactionId("recent"))
    recent_dir = recent.parent

    old_dir = store.ingress_path(FileNameStr("old.bin"), TransactionId("old")).parent
    old_time = time.time() - 1000
    os.utime(old_dir, (old_time, old_time))

    store._cleanup_dir(store._ingress_dir, ttl_seconds=900)

    assert recent_dir.exists()
    assert not old_dir.exists()
